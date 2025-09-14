/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsepc/hdr/mme/s1ap.h"
#include "srsran/asn1/gtpc.h"
#include "srsran/common/bcd_helpers.h"
#include "srsran/common/liblte_security.h"
#include "srsran/common/network_utils.h"
#include <cmath>
#include <inttypes.h> // for printing uint64_t
#include <random>

namespace srsepc {

s1ap*           s1ap::m_instance    = NULL;
pthread_mutex_t s1ap_instance_mutex = PTHREAD_MUTEX_INITIALIZER;

s1ap::s1ap() : m_s1mme(-1), m_next_mme_ue_s1ap_id(1), m_mme_gtpc(NULL), check_period(10), maxSize(10), crashCounter(0) {}

s1ap::~s1ap()
{
  return;
}

s1ap* s1ap::get_instance(void)
{
  pthread_mutex_lock(&s1ap_instance_mutex);
  if (m_instance == NULL) {
    m_instance = new s1ap();
  }
  pthread_mutex_unlock(&s1ap_instance_mutex);
  return (m_instance);
}

void s1ap::cleanup(void)
{
  pthread_mutex_lock(&s1ap_instance_mutex);
  if (NULL != m_instance) {
    delete m_instance;
    m_instance = NULL;
  }
  pthread_mutex_unlock(&s1ap_instance_mutex);
}

int s1ap::init(const s1ap_args_t& s1ap_args)
{
  m_s1ap_args = s1ap_args;
  srsran::s1ap_mccmnc_to_plmn(s1ap_args.mcc, s1ap_args.mnc, &m_plmn);

  std::random_device                      rd;
  std::mt19937                            generator(rd());
  std::uniform_int_distribution<uint32_t> distr(0, std::numeric_limits<uint32_t>::max());
  m_next_m_tmsi = distr(generator);

  // Get pointer to the HSS
  m_hss = hss::get_instance();

  // Init message handlers
  m_s1ap_mngmt_proc = s1ap_mngmt_proc::get_instance(); // Managment procedures
  m_s1ap_mngmt_proc->init();
  m_s1ap_nas_transport = s1ap_nas_transport::get_instance(); // NAS Transport procedures
  m_s1ap_nas_transport->init();
  m_s1ap_ctx_mngmt_proc = s1ap_ctx_mngmt_proc::get_instance(); // Context Management Procedures
  m_s1ap_ctx_mngmt_proc->init();
  m_s1ap_erab_mngmt_proc = s1ap_erab_mngmt_proc::get_instance(); // E-RAB Management Procedures
  m_s1ap_erab_mngmt_proc->init();
  m_s1ap_paging = s1ap_paging::get_instance(); // Paging
  m_s1ap_paging->init();

  // Get pointer to GTP-C class
  m_mme_gtpc = mme_gtpc::get_instance();

  // Initialize S1-MME
  m_s1mme = enb_listen();
  if (m_s1mme == SRSRAN_ERROR) {
    return SRSRAN_ERROR;
  }

  // Name the output logging path
  logging_path = s1ap_args.output_directory_name;
   // Name the logfile
  std::time_t now = std::time(nullptr);
  std::tm* localTime = std::localtime(&now);
  std::ostringstream filenameStream;
  filenameStream << logging_path << "_" << "data_" << std::put_time(localTime, "%y%m%d_%H%M%S") << ".csv";
  srsran::console("name of the logfile is %s\n", filenameStream.str().c_str());
  logfile_name = filenameStream.str();
 

  // Init PCAP
  m_pcap_enable = s1ap_args.pcap_enable;
  if (m_pcap_enable) {
    m_pcap.open(s1ap_args.pcap_filename.c_str());
  }
  m_logger.info("S1AP Initialized");
  return SRSRAN_SUCCESS;
}

void s1ap::stop()
{
  if (m_s1mme != -1) {
    close(m_s1mme);
  }
  std::map<uint16_t, enb_ctx_t*>::iterator enb_it = m_active_enbs.begin();
  while (enb_it != m_active_enbs.end()) {
    m_logger.info("Deleting eNB context. eNB Id: 0x%x", enb_it->second->enb_id);
    srsran::console("Deleting eNB context. eNB Id: 0x%x\n", enb_it->second->enb_id);
    delete enb_it->second;
    m_active_enbs.erase(enb_it++);
  }

  std::map<uint64_t, nas*>::iterator ue_it = m_imsi_to_nas_ctx.begin();
  while (ue_it != m_imsi_to_nas_ctx.end()) {
    m_logger.info("Deleting UE EMM context. IMSI: %015" PRIu64 "", ue_it->first);
    srsran::console("Deleting UE EMM context. IMSI: %015" PRIu64 "\n", ue_it->first);
    delete ue_it->second;
    m_imsi_to_nas_ctx.erase(ue_it++);
  }

  // Cleanup message handlers
  s1ap_mngmt_proc::cleanup();
  s1ap_nas_transport::cleanup();
  s1ap_ctx_mngmt_proc::cleanup();

  // PCAP
  if (m_pcap_enable) {
    m_pcap.close();
  }
  return;
}

int s1ap::get_s1_mme()
{
  return m_s1mme;
}

uint32_t s1ap::get_next_mme_ue_s1ap_id()
{
  return m_next_mme_ue_s1ap_id++;
}

int s1ap::enb_listen()
{
  /*This function sets up the SCTP socket for eNBs to connect to*/
  int                         sock_fd, err;
  struct sockaddr_in          s1mme_addr;
  struct sctp_event_subscribe evnts;

  m_logger.info("S1-MME Initializing");
  sock_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (sock_fd == -1) {
    srsran::console("Could not create SCTP socket\n");
    return SRSRAN_ERROR;
  }

  // Sets the data_io_event to be able to use sendrecv_info
  // Subscribes to the SCTP_SHUTDOWN event, to handle graceful shutdown
  bzero(&evnts, sizeof(evnts));
  evnts.sctp_data_io_event  = 1;
  evnts.sctp_shutdown_event = 1;
  if (setsockopt(sock_fd, IPPROTO_SCTP, SCTP_EVENTS, &evnts, sizeof(evnts))) {
    close(sock_fd);
    srsran::console("Subscribing to sctp_data_io_events failed\n");
    return SRSRAN_ERROR;
  }

  // S1-MME bind
  bzero(&s1mme_addr, sizeof(s1mme_addr));
  if (not srsran::net_utils::set_sockaddr(&s1mme_addr, m_s1ap_args.mme_bind_addr.c_str(), S1MME_PORT)) {
    close(sock_fd);
    m_logger.error("Invalid mme_bind_addr: %s", m_s1ap_args.mme_bind_addr.c_str());
    srsran::console("Invalid mme_bind_addr: %s\n", m_s1ap_args.mme_bind_addr.c_str());
    return SRSRAN_ERROR;
  }

  if (not srsran::net_utils::bind_addr(sock_fd, s1mme_addr)) {
    close(sock_fd);
    m_logger.error("Error binding SCTP socket");
    srsran::console("Error binding SCTP socket\n");
    return SRSRAN_ERROR;
  }

  // Listen for connections
  err = listen(sock_fd, SOMAXCONN);
  if (err != 0) {
    close(sock_fd);
    m_logger.error("Error in SCTP socket listen");
    srsran::console("Error in SCTP socket listen\n");
    return SRSRAN_ERROR;
  }

  return sock_fd;
}

bool s1ap::s1ap_tx_pdu(const asn1::s1ap::s1ap_pdu_c& pdu, struct sctp_sndrcvinfo* enb_sri)
{
  m_logger.debug("Transmitting S1AP PDU. eNB SCTP association Id: %d", enb_sri->sinfo_assoc_id);

  srsran::unique_byte_buffer_t buf = srsran::make_byte_buffer();
  if (buf == nullptr) {
    m_logger.error("Fatal Error: Couldn't allocate buffer for S1AP PDU.");
    return false;
  }
  asn1::bit_ref bref(buf->msg, buf->get_tailroom());
  if (pdu.pack(bref) != asn1::SRSASN_SUCCESS) {
    m_logger.error("Could not pack S1AP PDU correctly.");
    return false;
  }
  buf->N_bytes = bref.distance_bytes();

  ssize_t n_sent = sctp_send(m_s1mme, buf->msg, buf->N_bytes, enb_sri, MSG_NOSIGNAL);
  if (n_sent == -1) {
    srsran::console("Failed to send S1AP PDU. Error: %s\n", strerror(errno));
    m_logger.error("Failed to send S1AP PDU. Error: %s ", strerror(errno));
    return false;
  }

  if (m_pcap_enable) {
    m_pcap.write_s1ap(buf->msg, buf->N_bytes);
  }

  return true;
}

void s1ap::handle_s1ap_rx_pdu(srsran::byte_buffer_t* pdu, struct sctp_sndrcvinfo* enb_sri)
{
  // Save PCAP
  if (m_pcap_enable) {
    m_pcap.write_s1ap(pdu->msg, pdu->N_bytes);
  }

  // Get PDU type
  s1ap_pdu_t     rx_pdu;
  asn1::cbit_ref bref(pdu->msg, pdu->N_bytes);
  if (rx_pdu.unpack(bref) != asn1::SRSASN_SUCCESS) {
    m_logger.error("Failed to unpack received PDU");
    return;
  }

  switch (rx_pdu.type().value) {
    case s1ap_pdu_t::types_opts::init_msg:
      m_logger.info("Received Initiating PDU");
      handle_initiating_message(rx_pdu.init_msg(), enb_sri);
      break;
    case s1ap_pdu_t::types_opts::successful_outcome:
      m_logger.info("Received Succeseful Outcome PDU");
      handle_successful_outcome(rx_pdu.successful_outcome());
      break;
    case s1ap_pdu_t::types_opts::unsuccessful_outcome:
      m_logger.info("Received Unsucceseful Outcome PDU");
      // TODO handle_unsuccessfuloutcome(&rx_pdu.choice.unsuccessfulOutcome);
      break;
    default:
      m_logger.warning("Unhandled PDU type %d", rx_pdu.type().value);
  }
}

void s1ap::handle_initiating_message(const asn1::s1ap::init_msg_s& msg, struct sctp_sndrcvinfo* enb_sri)
{
  using init_msg_type_opts_t = asn1::s1ap::s1ap_elem_procs_o::init_msg_c::types_opts;

  switch (msg.value.type().value) {
    case init_msg_type_opts_t::s1_setup_request:
      m_logger.info("Received S1 Setup Request.");
      m_s1ap_mngmt_proc->handle_s1_setup_request(msg.value.s1_setup_request(), enb_sri);
      break;
    case init_msg_type_opts_t::init_ue_msg:
      m_logger.info("Received Initial UE Message.");
      m_s1ap_nas_transport->handle_initial_ue_message(msg.value.init_ue_msg(), enb_sri);
      break;
    case init_msg_type_opts_t::ul_nas_transport:
      m_logger.info("Received Uplink NAS Transport Message.");
      m_s1ap_nas_transport->handle_uplink_nas_transport(msg.value.ul_nas_transport(), enb_sri);
      break;
    case init_msg_type_opts_t::ue_context_release_request:
      m_logger.info("Received UE Context Release Request Message.");
      m_s1ap_ctx_mngmt_proc->handle_ue_context_release_request(msg.value.ue_context_release_request(), enb_sri);
      break;
    case init_msg_type_opts_t::ue_cap_info_ind:
      m_logger.info("Ignoring UE capability Info Indication.");
      break;
    case init_msg_type_opts_t::error_ind:
      // This is used for custom communicating in OTAFUZZ. 
      m_logger.info("Received Error Indication.");
      m_s1ap_ctx_mngmt_proc->handle_send_nas_test_message(msg.value.error_ind(), enb_sri);
      break;
    default:
      m_logger.error("Unhandled S1AP initiating message: %s", msg.value.type().to_string());
      srsran::console("Unhandled S1APinitiating message: %s\n", msg.value.type().to_string());
  }
}

void s1ap::handle_successful_outcome(const asn1::s1ap::successful_outcome_s& msg)
{
  using successful_outcome_type_opts_t = asn1::s1ap::s1ap_elem_procs_o::successful_outcome_c::types_opts;

  switch (msg.value.type().value) {
    case successful_outcome_type_opts_t::init_context_setup_resp:
      m_logger.info("Received Initial Context Setup Response.");
      m_s1ap_ctx_mngmt_proc->handle_initial_context_setup_response(msg.value.init_context_setup_resp());
      break;
    case successful_outcome_type_opts_t::ue_context_release_complete:
      m_logger.info("Received UE Context Release Complete");
      m_s1ap_ctx_mngmt_proc->handle_ue_context_release_complete(msg.value.ue_context_release_complete());
      break;
    default:
      m_logger.error("Unhandled successful outcome message: %s", msg.value.type().to_string());
  }
}

// eNB Context Managment
void s1ap::add_new_enb_ctx(const enb_ctx_t& enb_ctx, const struct sctp_sndrcvinfo* enb_sri)
{
  m_logger.info("Adding new eNB context. eNB ID %d", enb_ctx.enb_id);
  std::set<uint32_t> ue_set;
  enb_ctx_t*         enb_ptr = new enb_ctx_t;
  *enb_ptr                   = enb_ctx;
  m_active_enbs.emplace(enb_ptr->enb_id, enb_ptr);
  m_sctp_to_enb_id.emplace(enb_sri->sinfo_assoc_id, enb_ptr->enb_id);
  m_enb_assoc_to_ue_ids.emplace(enb_sri->sinfo_assoc_id, ue_set);
}

enb_ctx_t* s1ap::find_enb_ctx(uint16_t enb_id)
{
  std::map<uint16_t, enb_ctx_t*>::iterator it = m_active_enbs.find(enb_id);
  if (it == m_active_enbs.end()) {
    return nullptr;
  } else {
    return it->second;
  }
}

void s1ap::delete_enb_ctx(int32_t assoc_id)
{
  std::map<int32_t, uint16_t>::iterator it_assoc = m_sctp_to_enb_id.find(assoc_id);
  uint16_t                              enb_id   = it_assoc->second;

  std::map<uint16_t, enb_ctx_t*>::iterator it_ctx = m_active_enbs.find(enb_id);
  if (it_ctx == m_active_enbs.end() || it_assoc == m_sctp_to_enb_id.end()) {
    m_logger.error("Could not find eNB to delete. Association: %d", assoc_id);
    return;
  }

  m_logger.info("Deleting eNB context. eNB Id: 0x%x", enb_id);
  srsran::console("Deleting eNB context. eNB Id: 0x%x\n", enb_id);

  // Delete connected UEs ctx
  release_ues_ecm_ctx_in_enb(assoc_id);

  // Delete eNB
  delete it_ctx->second;
  m_active_enbs.erase(it_ctx);
  m_sctp_to_enb_id.erase(it_assoc);
  return;
}

// UE Context Management
bool s1ap::add_nas_ctx_to_imsi_map(nas* nas_ctx)
{
  std::map<uint64_t, nas*>::iterator ctx_it = m_imsi_to_nas_ctx.find(nas_ctx->m_emm_ctx.imsi);
  if (ctx_it != m_imsi_to_nas_ctx.end()) {
    m_logger.error("UE Context already exists. IMSI %015" PRIu64 "", nas_ctx->m_emm_ctx.imsi);
    return false;
  }
  if (nas_ctx->m_ecm_ctx.mme_ue_s1ap_id != 0) {
    std::map<uint32_t, nas*>::iterator ctx_it2 = m_mme_ue_s1ap_id_to_nas_ctx.find(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
    if (ctx_it2 != m_mme_ue_s1ap_id_to_nas_ctx.end() && ctx_it2->second != nas_ctx) {
      m_logger.error("Context identified with IMSI does not match context identified by MME UE S1AP Id.");
      return false;
    }
  }
  m_imsi_to_nas_ctx.emplace(nas_ctx->m_emm_ctx.imsi, nas_ctx);
  m_logger.debug("Saved UE context corresponding to IMSI %015" PRIu64 "", nas_ctx->m_emm_ctx.imsi);
  return true;
}

bool s1ap::add_nas_ctx_to_mme_ue_s1ap_id_map(nas* nas_ctx)
{
  if (nas_ctx->m_ecm_ctx.mme_ue_s1ap_id == 0) {
    m_logger.error("Could not add UE context to MME UE S1AP map. MME UE S1AP ID 0 is not valid.");
    return false;
  }
  std::map<uint32_t, nas*>::iterator ctx_it = m_mme_ue_s1ap_id_to_nas_ctx.find(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
  if (ctx_it != m_mme_ue_s1ap_id_to_nas_ctx.end()) {
    m_logger.error("UE Context already exists. MME UE S1AP Id %015" PRIu64 "", nas_ctx->m_emm_ctx.imsi);
    return false;
  }
  if (nas_ctx->m_emm_ctx.imsi != 0) {
    std::map<uint32_t, nas*>::iterator ctx_it2 = m_mme_ue_s1ap_id_to_nas_ctx.find(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
    if (ctx_it2 != m_mme_ue_s1ap_id_to_nas_ctx.end() && ctx_it2->second != nas_ctx) {
      m_logger.error("Context identified with MME UE S1AP Id does not match context identified by IMSI.");
      return false;
    }
  }
  m_mme_ue_s1ap_id_to_nas_ctx.emplace(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_ctx);
  m_logger.debug("Saved UE context corresponding to MME UE S1AP Id %d", nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
  return true;
}

bool s1ap::add_ue_to_enb_set(int32_t enb_assoc, uint32_t mme_ue_s1ap_id)
{
  std::map<int32_t, std::set<uint32_t> >::iterator ues_in_enb = m_enb_assoc_to_ue_ids.find(enb_assoc);
  if (ues_in_enb == m_enb_assoc_to_ue_ids.end()) {
    m_logger.error("Could not find eNB from eNB SCTP association %d", enb_assoc);
    return false;
  }
  std::set<uint32_t>::iterator ue_id = ues_in_enb->second.find(mme_ue_s1ap_id);
  if (ue_id != ues_in_enb->second.end()) {
    m_logger.error("UE with MME UE S1AP Id already exists %d", mme_ue_s1ap_id);
    return false;
  }
  ues_in_enb->second.insert(mme_ue_s1ap_id);
  m_logger.debug("Added UE with MME-UE S1AP Id %d to eNB with association %d", mme_ue_s1ap_id, enb_assoc);
  return true;
}

nas* s1ap::find_nas_ctx_from_mme_ue_s1ap_id(uint32_t mme_ue_s1ap_id)
{
  std::map<uint32_t, nas*>::iterator it = m_mme_ue_s1ap_id_to_nas_ctx.find(mme_ue_s1ap_id);
  if (it == m_mme_ue_s1ap_id_to_nas_ctx.end()) {
    return NULL;
  } else {
    return it->second;
  }
}

nas* s1ap::find_nas_ctx_from_imsi(uint64_t imsi)
{
  std::map<uint64_t, nas*>::iterator it = m_imsi_to_nas_ctx.find(imsi);
  if (it == m_imsi_to_nas_ctx.end()) {
    return NULL;
  } else {
    return it->second;
  }
}

void s1ap::release_ues_ecm_ctx_in_enb(int32_t enb_assoc)
{
  srsran::console("Releasing UEs context\n");
  std::map<int32_t, std::set<uint32_t> >::iterator ues_in_enb = m_enb_assoc_to_ue_ids.find(enb_assoc);
  std::set<uint32_t>::iterator                     ue_id      = ues_in_enb->second.begin();
  if (ue_id == ues_in_enb->second.end()) {
    srsran::console("No UEs to be released\n");
  } else {
    while (ue_id != ues_in_enb->second.end()) {
      std::map<uint32_t, nas*>::iterator nas_ctx = m_mme_ue_s1ap_id_to_nas_ctx.find(*ue_id);
      emm_ctx_t*                         emm_ctx = &nas_ctx->second->m_emm_ctx;
      ecm_ctx_t*                         ecm_ctx = &nas_ctx->second->m_ecm_ctx;

      m_logger.info(
          "Releasing UE context. IMSI: %015" PRIu64 ", UE-MME S1AP Id: %d", emm_ctx->imsi, ecm_ctx->mme_ue_s1ap_id);
      if (emm_ctx->state == EMM_STATE_REGISTERED) {
        m_mme_gtpc->send_delete_session_request(emm_ctx->imsi);
        emm_ctx->state = EMM_STATE_DEREGISTERED;
      }
      srsran::console("Releasing UE ECM context. UE-MME S1AP Id: %d\n", ecm_ctx->mme_ue_s1ap_id);
      ecm_ctx->state          = ECM_STATE_IDLE;
      ecm_ctx->mme_ue_s1ap_id = 0;
      ecm_ctx->enb_ue_s1ap_id = 0;
      ues_in_enb->second.erase(ue_id++);
    }
  }
}

bool s1ap::release_ue_ecm_ctx(uint32_t mme_ue_s1ap_id)
{
  nas* nas_ctx = find_nas_ctx_from_mme_ue_s1ap_id(mme_ue_s1ap_id);
  if (nas_ctx == NULL) {
    m_logger.error("Cannot release UE ECM context, UE not found. MME-UE S1AP Id: %d", mme_ue_s1ap_id);
    return false;
  }
  ecm_ctx_t* ecm_ctx = &nas_ctx->m_ecm_ctx;

  // Delete UE within eNB UE set
  std::map<int32_t, uint16_t>::iterator it = m_sctp_to_enb_id.find(ecm_ctx->enb_sri.sinfo_assoc_id);
  if (it == m_sctp_to_enb_id.end()) {
    m_logger.error("Could not find eNB for UE release request.");
    return false;
  }
  uint16_t                                         enb_id = it->second;
  std::map<int32_t, std::set<uint32_t> >::iterator ue_set = m_enb_assoc_to_ue_ids.find(ecm_ctx->enb_sri.sinfo_assoc_id);
  if (ue_set == m_enb_assoc_to_ue_ids.end()) {
    m_logger.error("Could not find the eNB's UEs.");
    return false;
  }
  ue_set->second.erase(mme_ue_s1ap_id);

  // Release UE ECM context
  m_mme_ue_s1ap_id_to_nas_ctx.erase(mme_ue_s1ap_id);
  ecm_ctx->state          = ECM_STATE_IDLE;
  ecm_ctx->mme_ue_s1ap_id = 0;
  ecm_ctx->enb_ue_s1ap_id = 0;

  m_logger.info("Released UE ECM Context.");
  return true;
}

bool s1ap::delete_ue_ctx(uint64_t imsi)
{
  nas* nas_ctx = find_nas_ctx_from_imsi(imsi);
  if (nas_ctx == NULL) {
    m_logger.info("Cannot delete UE context, UE not found. IMSI: %" PRIu64 "", imsi);
    return false;
  }

  // Make sure to release ECM ctx
  if (nas_ctx->m_ecm_ctx.mme_ue_s1ap_id != 0) {
    release_ue_ecm_ctx(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
  }

  // Delete UE context
  m_imsi_to_nas_ctx.erase(imsi);
  delete nas_ctx;
  m_logger.info("Deleted UE Context.");
  return true;
}

// UE Bearer Managment
void s1ap::activate_eps_bearer(uint64_t imsi, uint8_t ebi)
{
  std::map<uint64_t, nas*>::iterator ue_ctx_it = m_imsi_to_nas_ctx.find(imsi);
  if (ue_ctx_it == m_imsi_to_nas_ctx.end()) {
    m_logger.error("Could not activate EPS bearer: Could not find UE context");
    return;
  }
  // Make sure NAS is active
  uint32_t                           mme_ue_s1ap_id = ue_ctx_it->second->m_ecm_ctx.mme_ue_s1ap_id;
  std::map<uint32_t, nas*>::iterator it             = m_mme_ue_s1ap_id_to_nas_ctx.find(mme_ue_s1ap_id);
  if (it == m_mme_ue_s1ap_id_to_nas_ctx.end()) {
    m_logger.error("Could not activate EPS bearer: ECM context seems to be missing");
    return;
  }

  ecm_ctx_t* ecm_ctx = &ue_ctx_it->second->m_ecm_ctx;
  esm_ctx_t* esm_ctx = &ue_ctx_it->second->m_esm_ctx[ebi];
  if (esm_ctx->state != ERAB_CTX_SETUP) {
    m_logger.error(
        "Could not be activate EPS Bearer, bearer in wrong state: MME S1AP Id %d, EPS Bearer id %d, state %d",
        mme_ue_s1ap_id,
        ebi,
        esm_ctx->state);
    srsran::console(
        "Could not be activate EPS Bearer, bearer in wrong state: MME S1AP Id %d, EPS Bearer id %d, state %d\n",
        mme_ue_s1ap_id,
        ebi,
        esm_ctx->state);
    return;
  }

  esm_ctx->state = ERAB_ACTIVE;
  ecm_ctx->state = ECM_STATE_CONNECTED;
  m_logger.info("Activated EPS Bearer: Bearer id %d", ebi);
  return;
}

uint32_t s1ap::allocate_m_tmsi(uint64_t imsi)
{
  uint32_t m_tmsi = m_next_m_tmsi;
  m_next_m_tmsi   = (m_next_m_tmsi + 1) % UINT32_MAX;

  m_tmsi_to_imsi.emplace(m_tmsi, imsi);
  m_logger.debug("Allocated M-TMSI 0x%x to IMSI %015" PRIu64 ",", m_tmsi, imsi);
  return m_tmsi;
}

uint64_t s1ap::find_imsi_from_m_tmsi(uint32_t m_tmsi)
{
  std::map<uint32_t, uint64_t>::iterator it = m_tmsi_to_imsi.find(m_tmsi);
  if (it != m_tmsi_to_imsi.end()) {
    m_logger.debug("Found IMSI %015" PRIu64 " from M-TMSI 0x%x", it->second, m_tmsi);
    return it->second;
  } else {
    m_logger.debug("Could not find IMSI from M-TMSI 0x%x", m_tmsi);
    return SRSRAN_SUCCESS;
  }
}

void s1ap::print_enb_ctx_info(const std::string& prefix, const enb_ctx_t& enb_ctx)
{
  std::string mnc_str, mcc_str;

  if (enb_ctx.enb_name_present) {
    srsran::console("%s - eNB Name: %s, eNB id: 0x%x\n", prefix.c_str(), enb_ctx.enb_name.c_str(), enb_ctx.enb_id);
    m_logger.info("%s - eNB Name: %s, eNB id: 0x%x", prefix.c_str(), enb_ctx.enb_name.c_str(), enb_ctx.enb_id);
  } else {
    srsran::console("%s - eNB Id 0x%x\n", prefix.c_str(), enb_ctx.enb_id);
    m_logger.info("%s - eNB Id 0x%x", prefix.c_str(), enb_ctx.enb_id);
  }
  srsran::mcc_to_string(enb_ctx.mcc, &mcc_str);
  srsran::mnc_to_string(enb_ctx.mnc, &mnc_str);
  m_logger.info("%s - MCC:%s, MNC:%s, PLMN: %d", prefix.c_str(), mcc_str.c_str(), mnc_str.c_str(), enb_ctx.plmn);
  srsran::console("%s - MCC:%s, MNC:%s\n", prefix.c_str(), mcc_str.c_str(), mnc_str.c_str());
  for (int i = 0; i < enb_ctx.nof_supported_ta; i++) {
    for (int j = 0; i < enb_ctx.nof_supported_ta; i++) {
      m_logger.info("%s - TAC %d, B-PLMN 0x%x", prefix.c_str(), enb_ctx.tacs[i], enb_ctx.bplmns[i][j]);
      srsran::console("%s - TAC %d, B-PLMN 0x%x\n", prefix.c_str(), enb_ctx.tacs[i], enb_ctx.bplmns[i][j]);
    }
  }
  srsran::console("%s - Paging DRX %s\n", prefix.c_str(), enb_ctx.drx.to_string());
  return;
}

/*
 * Interfaces
 */

// GTP-C -> S1AP interface
bool s1ap::send_paging(uint64_t imsi, uint16_t erab_to_setup)
{
  m_s1ap_paging->send_paging(imsi, erab_to_setup);
  return true;
}

// GTP-C || NAS -> S1AP interface
bool s1ap::send_initial_context_setup_request(uint64_t imsi, uint16_t erab_to_setup)
{
  nas* nas_ctx = find_nas_ctx_from_imsi(imsi);
  if (nas_ctx == NULL) {
    m_logger.error("Error finding NAS context when sending initial context Setup Request");
    return false;
  }
  m_s1ap_ctx_mngmt_proc->send_initial_context_setup_request(nas_ctx, erab_to_setup);
  return true;
}

// NAS -> S1AP interface
bool s1ap::send_ue_context_release_command(uint32_t mme_ue_s1ap_id)
{
  nas* nas_ctx = find_nas_ctx_from_mme_ue_s1ap_id(mme_ue_s1ap_id);
  if (nas_ctx == NULL) {
    m_logger.error("Error finding NAS context when sending UE Context Setup Release");
    return false;
  }
  m_s1ap_ctx_mngmt_proc->send_ue_context_release_command(nas_ctx);
  return true;
}

bool s1ap::send_error_indication(nas* nas_ctx, uint16_t cause)
{
  if (nas_ctx == NULL) {
    m_logger.error("Error finding NAS context when sending Error Indication");
    return false;
  }
  
  m_s1ap_ctx_mngmt_proc->send_error_indication(nas_ctx, cause);
  return true;
} 

bool s1ap::send_erab_release_command(uint32_t               enb_ue_s1ap_id,
                                     uint32_t               mme_ue_s1ap_id,
                                     std::vector<uint16_t>  erabs_to_be_released,
                                     struct sctp_sndrcvinfo enb_sri)
{
  return m_s1ap_erab_mngmt_proc->send_erab_release_command(
      enb_ue_s1ap_id, mme_ue_s1ap_id, erabs_to_be_released, enb_sri);
}

bool s1ap::send_erab_modify_request(uint32_t                     enb_ue_s1ap_id,
                                    uint32_t                     mme_ue_s1ap_id,
                                    std::map<uint16_t, uint16_t> erabs_to_be_modified,
                                    srsran::byte_buffer_t*       nas_msg,
                                    struct sctp_sndrcvinfo       enb_sri)
{
  return m_s1ap_erab_mngmt_proc->send_erab_modify_request(
      enb_ue_s1ap_id, mme_ue_s1ap_id, erabs_to_be_modified, nas_msg, enb_sri);
}

bool s1ap::send_downlink_nas_transport(uint32_t               enb_ue_s1ap_id,
                                       uint32_t               mme_ue_s1ap_id,
                                       srsran::byte_buffer_t* nas_msg,
                                       struct sctp_sndrcvinfo enb_sri)
{
  return m_s1ap_nas_transport->send_downlink_nas_transport(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_msg, enb_sri);
}

bool s1ap::send_nas_test_message_from_py(nas* nas_ctx){

  // If NAS timer for ID Req oracle is running, stop it
  if (nas_ctx->m_mme->is_nas_timer_running(T_NAS_ORACLE_TIMEOUT, nas_ctx->m_emm_ctx.imsi)){
    nas_ctx->m_mme->remove_nas_timer(T_NAS_ORACLE_TIMEOUT, nas_ctx->m_emm_ctx.imsi);
  }

  if (nas_ctx->m_reattach_enabled){
    if (!nas_ctx->m_mme->is_nas_timer_running(T_DoOTA, nas_ctx->m_emm_ctx.imsi)){
      // When the DoOTA timer is expired, stop sending NAS messages
      srsran::console("DoOTA timer expired, stop sending NAS messages\n");
      return true;
    }
  }

  // If in backtracking mode, stop it

  // Enable backtracking if not doing replay mode
  if (!nas_ctx->m_replay_mode && is_backtracking){
    send_nas_test_message_backtracking(nas_ctx);
    return true;
  }

  if (nas_ctx->m_replay_mode){
    check_period = 2;
  }
 
  srsran::unique_byte_buffer_t nas_buffer = srsran::make_byte_buffer();

  std::string nas_id_req = "075501";

  std::string nas_normal = "075502";
  // std::string nas_0day = "0766";
  std::string nas_0day = "075502";

  std::string payload;

  nas_ctx->msg_cnt++;
  total_sent_msg++;
  
  if (total_sent_msg_inc_oracle % check_period == 0){
    payload = nas_id_req;

    m_logger.info("* Sending NAS liveness check: %s\n", payload.c_str());
    srsran::console("* Sending NAS liveness check: %s\n", payload.c_str());
  } else {
    get_test_msg_from_file(payload);
   
    

    m_logger.info("Sending NAS payload : %s\n", payload.c_str());

    if (payload.length()/2 < 40){
      srsran::console("Payload bytes: %s\n", payload.c_str());
    } else {
      srsran::console("Payload bytes: %s ... %s\n", payload.substr(0, 20).c_str(), payload.substr(payload.length()-20, payload.length()).c_str());
    }
    srsran::console("Payload length: %zu (B), This session: %d, Total: %d\n", (payload.length()/2), nas_ctx->msg_cnt, total_sent_msg);
  }

  total_sent_msg_inc_oracle++;

  if (nas_ctx->m_test_state == POST_AKA_STATE){
    nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED);
  } else {
    nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS);
  }
  nas_ctx->m_s1ap->send_downlink_nas_transport(nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer.get(), nas_ctx->m_ecm_ctx.enb_sri);

  // When doing measurement, log the timestamp for all the messages we send 
  // In normal case, we log only for the test messages
  if (m_s1ap_args.reattach_measure){
    std::string XX = "x";
    log_timestamp(XX);
  }

  return true;
}

bool s1ap::send_nas_test_message_backtracking(nas* nas_ctx){
  m_logger.info("Backtracking NAS test message\n");
  std::string payload_msgName_path, payload;

  // Get the backtracking queue
  std::vector<std::string> backtracking_queue = get_recent_messages();

  // Increase the backtracking number
  backtracking_num++;
  backtracking_num_total++;

  // Check if the backtracking is done
  if (backtracking_num > backtracking_queue.size()){
    m_logger.info("Backtracking is done\n");
    srsran::console("Backtracking is done\n");
    is_backtracking = false;
    backtracking_num = 0;
    backtracking_num_total = 0;
    backtracking_msg = "";
    oracle_cnt = 0;

    // Clear the test message queue as well
    test_message_queue = {};

    // Send NAS ID Req oracle to start again
    // TODO: Check the logic
    send_nas_id_req(nas_ctx);

    return true;
  }

  // For each backtracking message, check the oracle
  if (backtracking_num_total % 2 == 0){
    send_nas_id_req(nas_ctx);
    // backtracking_num_total++;
    backtracking_num--;
    srsran::console("[Backtracking Oracle #%d]", backtracking_num_total/2);

    return true;

  } else{
    // When sending a backtracking message
    // Get the payload from the payload_msgName_path
    payload_msgName_path = backtracking_queue[backtracking_queue.size() - backtracking_num];
    backtracking_msg = payload_msgName_path;
  }

    std::istringstream inputStream(payload_msgName_path);
  
  if (!std::getline(inputStream, payload, ',')) {
    m_logger.error("Error: could not get payload from payload_msgName_path\n");
    return false;
  }

  // Log the payload
  m_logger.info("[Backtracking #%d] Sending payload: %s\n", backtracking_num, payload.c_str());
  m_logger.info("[Backtracking #%d] Payload length: %zu (B), This session: %d, Total: %d\n", backtracking_num, (payload.length()/2), nas_ctx->msg_cnt, total_sent_msg);

  if (payload.length()/2 < 40){
    srsran::console("[Backtracking #%d] Payload bytes: %s\n", backtracking_num, payload.c_str());
  } else {
    srsran::console("[Backtracking #%d] Payload bytes: %s ... %s\n", backtracking_num, payload.substr(0, 20).c_str(), payload.substr(payload.length()-20, payload.length()).c_str()); 
  }
  srsran::console("[Backtracking #%d] Payload length: %zu (B), This session: %d, Total: %d\n", backtracking_num, (payload.length()/2), nas_ctx->msg_cnt, total_sent_msg);

  // Send the payload
  srsran::unique_byte_buffer_t nas_buffer = srsran::make_byte_buffer();
  if (nas_ctx->m_test_state == POST_AKA_STATE){
    nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED);
  } else {
    nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS);
  }
  nas_ctx->m_s1ap->send_downlink_nas_transport(nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer.get(), nas_ctx->m_ecm_ctx.enb_sri);

  // When doing measurement, log the timestamp for all the messages we send 
  // In normal case, we log only for the test messages
  if (m_s1ap_args.reattach_measure){
    std::string XX = "x";
    log_timestamp(XX);
  }


  return true;

}

bool s1ap::handle_nas_oracle(nas* nas_ctx){

  srsran::console("NAS oracle triggered!\n");
  m_logger.info("NAS oracle triggered!\n");

  oracle_cnt++;
  uint8_t max_oracle_trial = 2;

  if (oracle_cnt >= max_oracle_trial){
    
    if (!is_backtracking){
      // If not, turn on the backtracking mode
      is_backtracking = true;
      backtracking_num = 0;
      srsran::console("Backtracking mode activated\n");
      m_logger.info("Backtracking mode activated\n");

      // Start sending the message
      // First, send NAS ID Req oracle again. If there is no response, 

    } else {
      // Handle when the NAS ID Req oracle is triggered during the backtracking
      m_logger.info("Found the candidate");
      srsran::console("Found the candidate\n");
      save_recent_messages(logging_path, backtracking_msg, backtracking_num);
    }

  } else {
    // Optional: If you want to try ID Req oracle multiple times before backtracking
    std::string payload = "075501";
    srsran::unique_byte_buffer_t nas_buffer = srsran::make_byte_buffer();
    if (nas_ctx->m_test_state == POST_AKA_STATE){
      nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED);
    } else {
      nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS);
    }

    nas_ctx->m_s1ap->send_downlink_nas_transport(nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer.get(), nas_ctx->m_ecm_ctx.enb_sri);

    // When doing measurement, log the timestamp for all the messages we send 
    // In normal case, we log only for the test messages
    if (m_s1ap_args.reattach_measure){
      std::string XX = "x";
    log_timestamp(XX);
    }
  }

  return true;
}

void s1ap::send_nas_id_req(nas* nas_ctx){
  
    srsran::unique_byte_buffer_t nas_buffer = srsran::make_byte_buffer();
    std::string payload = "075501";
  
    if (nas_ctx->m_test_state == POST_AKA_STATE){
      nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED);
    } else {
      nas_ctx->pack_test_ota_message(nas_buffer.get(), payload, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS);
    }
  
    nas_ctx->m_s1ap->send_downlink_nas_transport(nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer.get(), nas_ctx->m_ecm_ctx.enb_sri);

    // When doing measurement, log the timestamp for all the messages we send 
    // In normal case, we log only for the test messages
    if (m_s1ap_args.reattach_measure){
      std::string XX = "x";
      log_timestamp(XX);
    }

    return;

}

bool s1ap::send_paging_message(nas* nas_ctx){

  send_paging(nas_ctx->m_emm_ctx.imsi, 0);

  return true;
}

// bool s1ap::send_detach_request_for_sr(nas* nas_ctx){

//   srsran::unique_byte_buffer_t nas_buffer = srsran::make_byte_buffer();

//   nas_ctx->pack_detach_request(nas_buffer.get());
//   nas_ctx->m_s1ap->send_downlink_nas_transport(nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer.get(), nas_ctx->m_ecm_ctx.enb_sri);
  
//   return true;
// }

bool s1ap::expire_nas_timer(enum nas_timer_type type, uint64_t imsi)
{
  nas* nas_ctx = find_nas_ctx_from_imsi(imsi);
  if (nas_ctx == NULL) {
    m_logger.error("Error finding NAS context to handle timer");
    return false;
  }
  bool err = nas_ctx->expire_timer(type);
  return err;
}

void s1ap::get_test_msg_from_file(std::string& payload){

  // !inputTestFile.is_open()
  std::string indexFileName = "testFileIndex";

  // Check if the test file is opened
  if (!isTestFileOpen){
    m_logger.info("Opening a new file");
    srsran::console("Opening a new file\n");

    // Open the idx file to get the details for opening the test file
    std::ifstream indexFile(indexFileName);
    if(!indexFile){
      m_logger.error("Error: could not open file");
      srsran::console("Error: could not open file\n");
      return;
    }

    // Read the first line of the idx file
    std::string line;
    if (std::getline(indexFile, line)){
      std::istringstream lineStream(line);

      // Get the name of the test file to open
      if (std::getline(lineStream, testFileName, ',')){

        // check if there are more values
        // this happends when the program is terminated due to the error and restarted. 
        if (!lineStream.eof()){
          if (lineStream >> curLineNum && lineStream.ignore() && (lineStream >> totalLineNum)){
            m_logger.warning("The program was terminated due to the error. Restarting from the line %d", curLineNum);
            srsran::console("The program was terminated due to the error. Restarting from the line %d\n", curLineNum);
            
            // Open the test file
            inputTestFile.open(testFileName);
            isTestFileOpen = true;

            firstPos = inputTestFile.tellg();

            // Move the file pointer to the line number
            for (int i = 0; i < curLineNum; i++){
              std::getline(inputTestFile, line);
            }
            // Store the file pointer, curPos 
            curPos = inputTestFile.tellg();

          } else {
            m_logger.error("Invalid format in the first line of %s", indexFileName.c_str());
            srsran::console("Invalid format in the first line of %s\n", indexFileName.c_str());
          }
        } else{
          // Reading the testfile for the first time. Usually here.
          m_logger.info("Opening %s for the first time", testFileName.c_str());
          srsran::console("Opening %s for the first time\n", testFileName.c_str());

          inputTestFile.open(testFileName);
          isTestFileOpen = true;

          firstPos = inputTestFile.tellg();

          // Read the first line of the test file
          if (inputTestFile){
            if (inputTestFile >> totalLineNum){
              indexFile.close();

              std::ofstream indexFile(indexFileName);
              if (indexFile){
                // Update the firstline of the indexFile
                indexFile << testFileName << "," << totalLineNum << std::endl;
              } else{
                m_logger.error("Failed to open %s for writing", indexFileName.c_str());
                srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
              }
              indexFile.close();
            } else {
              m_logger.error("Empty file %s or failed to read the first line.", testFileName.c_str());
              srsran::console("Empty file %s or failed to read the first line.\n", testFileName.c_str());
            }
          } else {
            m_logger.error("Failed to open %s", testFileName.c_str());
            srsran::console("Failed to open %s\n", testFileName.c_str());
          }

        // Moving the file pointer to the first packet.
        std::getline(inputTestFile, line);
        }
      } else {
        m_logger.error("Empty file %s or failed to read the first line.", indexFileName.c_str());
        srsran::console("Empty file %s or failed to read the first line.\n", indexFileName.c_str());
      }
    }
  }

  std::string line;
  srsran::console("Total line num is %d\n", totalLineNum);
  
  // When we reached the end of the file, update the index file. 
  if (curLineNum > totalLineNum){
    // Reached the end of the file. 
    std::ofstream indexFile(indexFileName);

    // log that this is opened
    m_logger.info("Reached the end of the file. Opening a new file");
    srsran::console("Reached the end of the file. Opening a new file\n");

    std::string newFileName;
    if (indexFile){
      newFileName = incrementFilename(testFileName);
      indexFile << newFileName << std::endl;
      // log the name of new file
      m_logger.info("Reading New file %s", newFileName.c_str());
      srsran::console("Reading New file %s\n", newFileName.c_str());

      indexFile.close();
      
      m_logger.info("Reached the end of the file. Closing the file %s and opening a new file %s", testFileName.c_str(), newFileName.c_str());
      srsran::console("Reached the end of the file. Closing the file %s and opening a new file %s\n", testFileName.c_str(), newFileName.c_str());
    } else {
      m_logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
    }

    // Close the current file
    inputTestFile.close();
    isTestFileOpen = false;

    // inputTestFile.open(newFileName);

    // Do what we do when we open a new file
    m_logger.info("Opening %s for the first time", newFileName.c_str());
    srsran::console("Opening %s for the first time\n", newFileName.c_str());

    inputTestFile.open(newFileName);
    isTestFileOpen = true;
    curLineNum = 1;
    testFileName = newFileName;

    firstPos = inputTestFile.tellg();

    // Read the first line of the test file
    if (inputTestFile){
      if (inputTestFile >> totalLineNum){
        indexFile.close();

        std::ofstream indexFile(indexFileName);
        if (indexFile){
          // Update the firstline of the indexFile
          indexFile << newFileName << "," << totalLineNum << std::endl;
        } else{
          m_logger.error("Failed to open %s for writing", indexFileName.c_str());
          srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
        }
        indexFile.close();
      } else {
        m_logger.error("Empty file %s or failed to read the first line.", newFileName.c_str());
        srsran::console("Empty file %s or failed to read the first line.\n", newFileName.c_str());
      }
    } else {
      m_logger.error("Failed to open %s", newFileName.c_str());
      srsran::console("Failed to open %s\n", newFileName.c_str());
    }
    // Skipping the first line
    std::getline(inputTestFile, line);
  }

  // getline and update the first line
  std::getline(inputTestFile, line);
  m_logger.info("Get line from %s", testFileName.c_str());
  srsran::console("Get line from %s\n", testFileName.c_str());
  srsran::console("Line is : %s\n", line.c_str());

  // Update the current line number
  curLineNum++;

  // Update the index file
  std::ofstream indexFile(indexFileName);
  if (indexFile){
    indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
    indexFile.close();
  } else {
    m_logger.error("Failed to open %s for writing", indexFileName.c_str());
    srsran::console("Failed to open %s for writing", indexFileName.c_str());
  }

  // Split the line into components using ',' as the delimiter and pass it to the payload
  srsran::console("Debug: line is %s\n", line.c_str());

  std::istringstream lineStream(line);
  std::string numbering, filepayload, msgName, fieldName;
  std::getline(lineStream, numbering, ',');
  std::getline(lineStream, filepayload, ',');
  std::getline(lineStream, msgName, ',');
  std::getline(lineStream, fieldName, ',');

  // This function is used for hard blacklist certain message during normal test
  if (m_s1ap_args.blacklist_mode){
    bool skipMessage = false;

    std::vector<std::string> skipMsgPayloads = {"0745", "0752"};
    // 0745: DetachRequest
    // 0752: auth req
    // "074b", "074e"
    // std::vector<std::string> skipMsgPayloads = {};

    for (const std::string& skipMsgPayload : skipMsgPayloads){
      if (filepayload.compare(0, skipMsgPayload.length(), skipMsgPayload) == 0){
        skipMessage = true;
        srsran::console("Skipping detected\n"); 
      }
    }

    if (skipMessage){
      
      do {

        // getline and update the first line
        if (!std::getline(inputTestFile, line)) {
          srsran::console("No more lines to read!");
          break;
        }
      
        curLineNum++;
        m_logger.info("Get line from %s", testFileName.c_str());
        srsran::console("Get line from %s\n", testFileName.c_str());

        std::istringstream lineStream3(line);

        std::getline(lineStream3, numbering, ',');
        std::getline(lineStream3, filepayload, ',');
        std::getline(lineStream3, msgName, ',');
        std::getline(lineStream3, fieldName, ',');

        payload = filepayload;
        


        skipMessage = false;

        for (const std::string& skipMsgPayload : skipMsgPayloads){
          if (filepayload.compare(0, skipMsgPayload.length(), skipMsgPayload) == 0){
            skipMessage = true;
            srsran::console("Skipping detected\n");
          }
        }
      } while (skipMessage);
      
      // print the payload
      srsran::console("Debug: line is %s\n", line.c_str());
      srsran::console("msgName is %s\n", msgName.c_str());
      srsran::console("fieldName is %s\n", fieldName.c_str());
      srsran::console("payload is %s\n", payload.c_str());
      srsran::console("numbering is %s\n", numbering.c_str());
    } else {
      payload = filepayload;
    }
    
    // Update the index file
    std::ofstream indexFile(indexFileName);
    if (indexFile){
      indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
      indexFile.close();
    } else {
      m_logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing", indexFileName.c_str());
    }

    // Split the line into components using ',' as the delimiter and pass it to the payload
    srsran::console("Debug: line is %s\n", line.c_str());


  }
    
  if (m_s1ap_args.replay_mode){
    // During replay, support skipping certain msg+field combinations

    bool skipThisMessage = false;

    // A32
    // std::vector<std::string> skipMsgFields = {"EMMInformation,NetShortName", 
    // "EMMInformation,EMMHeader",
    // "EMMDLGenericNASTransport,AddInfo",
    // "EMMInformation,LocalTimeZone",
    // "EMMInformation,UnivTimeAndTimeZone",
    // "EMMInformation,NetFullName",
    // "EMMInformation,DLSavingTime",
    // "EMMDLGenericNASTransport,GenericContainer",
    // "EMMDetachRequestMT",
    // "EMMInformation"};

    // S21 post
    // std::vector<std::string> skipMsgFields = {
    //   "EMMAttachAccept,EmergNumList", // Bug
    //   "EMMAuthenticationReject,EMMHeader", // Bug
    //   "EMMAuthenticationRequest,AUTN",
    //   "EMMDetachAccept,EMMHeader", // Bug
    //   "EMMDetachRequestMT", // Not bug: however, detached and no more response
    //   "EMMServiceReject,EMMCause", //  Not bug, bug sends service request
    //   "EMMServiceReject"
    // };

    // S21 pre
    // std::vector<std::string> skipMsgFields = {
    //   "EMMAuthenticationReject,EMMHeader", // Bug
    //   "EMMDetachAccept,EMMHeader", // Bug
    //   // "EMMAuthenticationRequest,AUTN",  // Not a bug, Sometimes, UE does not responsed after this 
    //   "EMMDetachRequestMT", // Not bug: however, detached and no more response
    // };

    // Note8 post
    std::vector<std::string> skipMsgFields = {
      "EMMAttachAccept,EmergNumList", // Bug
      "EMMAuthenticationReject,EMMHeader", // Bug
      "EMMAuthenticationRequest",
      "EMMDetachAccept,EMMHeader", // Bug
      "EMMDetachRequestMT", // Not bug: however, detached and no more response
      // "EMMServiceReject,EMMCause", //  Not bug, bug sends service request
      "EMMServiceReject"
    };
    // 0746 (bug)

    // std::vector<std::string> skipMsgFields = {
    //   // "EMMInformation" // Bug
    // };

    for (const std::string& skipMsgField : skipMsgFields){
      if (skipMsgField == msgName+","+fieldName || skipMsgField == msgName){
        skipThisMessage = true;
        srsran::console("Skipping detected\n");
      }
    }

    if (skipThisMessage){
      
      do {

        // getline and update the first line
        if (!std::getline(inputTestFile, line)) {
          srsran::console("No more lines to read!");
          break;
        }
      
        curLineNum++;
        m_logger.info("Get line from %s", testFileName.c_str());
        srsran::console("Get line from %s\n", testFileName.c_str());

        std::istringstream lineStream2(line);

        std::getline(lineStream2, numbering, ',');
        std::getline(lineStream2, filepayload, ',');
        std::getline(lineStream2, msgName, ',');
        std::getline(lineStream2, fieldName, ',');

        payload = filepayload;
        


        skipThisMessage = false;

        for (const std::string& skipMsgField : skipMsgFields){
          if (skipMsgField == msgName+","+fieldName || skipMsgField == msgName){
            skipThisMessage = true;
            srsran::console("Skipping detected\n");
          }
        }
      } while (skipThisMessage);
      srsran::console("DEBUGHERE\n");
      // print the payload
      srsran::console("Debug: line is %s\n", line.c_str());
      srsran::console("msgName is %s\n", msgName.c_str());
      srsran::console("fieldName is %s\n", fieldName.c_str());
      srsran::console("payload is %s\n", payload.c_str());
      srsran::console("numbering is %s\n", numbering.c_str());
    } else {
      payload = filepayload;
    }
    srsran::console("HERE\n");
    // Update the index file
    std::ofstream indexFile(indexFileName);
    if (indexFile){
      indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
      indexFile.close();
    } else {
      m_logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing", indexFileName.c_str());
    }

    // Split the line into components using ',' as the delimiter and pass it to the payload
    srsran::console("Debug: line is %s\n", line.c_str());

  }
    


  payload = filepayload;

  // Put the message to the candidates queue
  put_test_message_queue(payload+","+msgName+","+fieldName);

  // When doing measurement, log the timestamp for all the messages we send 
  // In normal case, we log only for the test messages
  if (!m_s1ap_args.reattach_measure){
    log_timestamp(numbering);
  }
  

}

std::string s1ap::incrementFilename(const std::string& filename){
  size_t pos = filename.find_first_of("0123456789");
  if (pos != std::string::npos){
    std::string prefix = filename.substr(0, pos);
    std::string numStr = filename.substr(pos);
    int num = stoi(numStr);
    num++;
    return prefix + std::to_string(num);
  }
  return filename;
}

void s1ap::put_test_message_queue(const std::string& test_message){
  test_message_queue.push(test_message);

  while (test_message_queue.size() > maxSize) {
    test_message_queue.pop();
  }

}

std::vector<std::string> s1ap::get_recent_messages(){
  std::vector<std::string> recent_ten_messages;
  std::queue<std::string> tempQueue = test_message_queue;

  while (!tempQueue.empty()){
    recent_ten_messages.push_back(tempQueue.front());
    tempQueue.pop();
  }

  if (recent_ten_messages.size() > 10){
    recent_ten_messages.erase(recent_ten_messages.begin(), recent_ten_messages.end() - 10);
  }

  return recent_ten_messages;
}

void s1ap::save_recent_messages(const std::string& directoryPath, const std::string& candidate, int order){

  // Check if directoryPath exists. 
  struct stat st;
  if (stat(directoryPath.c_str(), &st) != 0){
    // Directory doesn't exist, so create it
    if (mkdir(directoryPath.c_str(), 0775) == 0){
      m_logger.info("Created directory %s", directoryPath.c_str());
    } else {
      m_logger.error("1Failed to create directory %s", directoryPath.c_str());
      srsran::console("1Failed to create directory %s\n", directoryPath.c_str());
      perror("mkdir");
    }

    // Also create a directory for crashes which is inside the directoryPath
    std::string crashesDirectory = directoryPath + "/crashes";
    if (mkdir(crashesDirectory.c_str(), 0775) == 0){
      m_logger.info("Created directory %s", crashesDirectory.c_str());
    } else {
      m_logger.error("2Failed to create directory %s", crashesDirectory.c_str());
      srsran::console("2Failed to create directory %s\n", crashesDirectory.c_str());
      perror("mkdir");
    }
  }

  // Increment the crash counter
  ++crashCounter;

  json jsonData;
  std::queue<std::string> tempQueue = test_message_queue;
  int payloadCounter = 0;

  while (!tempQueue.empty()){
    std::string payload_and_path = tempQueue.front();
    tempQueue.pop();

    // Split the input string into payload and path elements
    std::istringstream inputStream(payload_and_path);
    std::string payload, msgName, pathes;

    if (std::getline(inputStream, payload, ',')){
      if (std::getline(inputStream, msgName, ',')) {
        if (std::getline(inputStream, pathes, ',')) {
          // Split the pathes string into individual elements
          std::vector<std::string> pathElements;
          std::istringstream pathStream(pathes);
          std::string pathElement;

          while (std::getline(pathStream, pathElement, ',')){
            pathElements.push_back(pathElement);
          }

          // Create a JSON array from the path elements
          json pathArray = json::array();

          for (const std::string& pathElement : pathElements){
            pathArray.push_back(pathElement);
          }

          // Add the payload and path array to the json object
          jsonData[std::to_string(payloadCounter)] = {
            {"Payload", payload},
            {"Message", msgName},
            {"Path", pathArray}
          };

        } else {
          m_logger.error("Failed to get pathes from the input string");
          srsran::console("Failed to get pathes from the input string\n");
        }
      } else {
        m_logger.error("Failed to get msgName from the input string");
        srsran::console("Failed to get msgName from the input string\n");
      }
    } else {
      m_logger.error("Failed to get payload from the input string");
      srsran::console("Failed to get payload from the input string\n");
    }

    payloadCounter++;
  }

  if ((!candidate.empty())){
    // Split the input string into payload and path elements
    std::istringstream inputStream(candidate);
    std::string can_payload, can_msgName, can_pathes;

    // Parse the Best candidate string
    if (std::getline(inputStream, can_payload, ',')){
      if (std::getline(inputStream, can_msgName, ',')) {
        if (std::getline(inputStream, can_pathes, ',')) {
        } else {
          m_logger.error("Failed to get pathes from the input string");
          srsran::console("Failed to get pathes from the input string\n");
        }
      } else {
        m_logger.error("Failed to get msgName from the input string");
        srsran::console("Failed to get msgName from the input string\n");
      }
    } else {
      m_logger.error("Failed to get payload from the input string");
      srsran::console("Failed to get payload from the input string\n");
    }

    if (order == 0){
      jsonData["Best Candidate"] = {
        {"Payload", can_payload},
        {"Message", can_msgName},
        {"Path", can_pathes}
      };
    }  else {
      jsonData["Candidate " + std::to_string(order)] = {
        {"Payload", can_payload},
        {"Message", can_msgName},
        {"Path", can_pathes}
      };
    }
  } 

  std::stringstream directoryStream;
  directoryStream << directoryPath << "/crashes/crash_" << crashCounter;
  std::string crashDirectory = directoryStream.str();

  // Check if directory exists, and create it if it doesn't
  if (stat(crashDirectory.c_str(), &st) != 0){
    // Directory doesn't exist, so create it
    if (mkdir(crashDirectory.c_str(), 0775) == 0){
      m_logger.info("Created directory %s", crashDirectory.c_str());
    } else {
      m_logger.error("1Failed to create directory %s", crashDirectory.c_str());
      srsran::console("1Failed to create directory %s\n", crashDirectory.c_str());
      perror("mkdir");
    }
  } else {
    // Crash directory exists, so create a new directory with a new crash number
    crashDirectory = GetNextCrashDirectory(directoryPath);

  }

  // Update the crash_count file. 
  std::string countFilePath = directoryPath + "/crashes/crash_count.txt";
  std::ofstream updatedCountFile(countFilePath);
  updatedCountFile << crashCounter;
  updatedCountFile.close();

  // Update the candidate_list file
  std::string log_candidate_list_file_name = directoryPath + "/candidate_list.txt";
  std::ofstream updatedCandidateListFile;
  updatedCandidateListFile.open(log_candidate_list_file_name, std::ios::app);
  updatedCandidateListFile << testFileName << "," << (curLineNum - (int)backtracking_num) << std::endl;
  updatedCandidateListFile.close();


  // Update the candidate_list_file
  std::string filename = crashDirectory + "/candidates.json";
  std::ofstream file(filename);
  file << jsonData.dump(4);
  file.close();
}

// This is called when a directory alread exists during saving. 
std::string s1ap::GetNextCrashDirectory(const std::string& directoryPath){
  // If the directory exists
  std::string countFilePath = directoryPath + "/crashes/crash_count.txt";
  int nextCrashNumber = 0;

  // Read the next number from the file
  // TODO: Update this file
  std::ifstream countFile(countFilePath);
  if (countFile.is_open()) {
    countFile >> nextCrashNumber;
    countFile.close();
  } else {
    m_logger.error("Failed to open %s", countFilePath.c_str());
    srsran::console("Failed to open %s\n", countFilePath.c_str());
  }

  // Increament the count
  nextCrashNumber++;

  std::stringstream nextCrashDirStream;
  nextCrashDirStream << directoryPath << "/crashes/crash_" << nextCrashNumber;
  std::string nextCrashDirectory = nextCrashDirStream.str();

  // Create the next crash directory
  if (mkdir(nextCrashDirectory.c_str(), 0775) == 0){
    m_logger.info("Created directory %s", nextCrashDirectory.c_str());
    // Update the count in the file
    std::ofstream updatedCountFile(countFilePath);
    updatedCountFile.close();

    // Also update the crashCounter
    crashCounter = nextCrashNumber;
  } else {
    m_logger.error("Failed to create directory %s", nextCrashDirectory.c_str());
    srsran::console("Failed to create directory %s\n", nextCrashDirectory.c_str());
  }

  return nextCrashDirectory;

  }

  void s1ap::blacklist_test_cases(std::string& blacklist_msgName_path){
    // Split the input string into payload, msgName and path elements
    std::istringstream inputStream(blacklist_msgName_path);
    std::string payload, blacklist_msgName_and_paths;

    // Parse the Best candidate string
    if (std::getline(inputStream, payload, ',')){
      if (std::getline(inputStream, blacklist_msgName_and_paths)) {
      } else {
        m_logger.error("Failed to get msgName and pathes from the input string");
        srsran::console("Failed to get msgName and pathes from the input string\n");
      }
    } else {
      m_logger.error("Failed to get payload from the input string");
      srsran::console("Failed to get payload from the input string\n");
    }

    // Skip the messages in the inputTestFile that have the same msgName and pathes with the blacklist_msgName_path
    // First, do std::getline(inputTestFile, line); and compare the msgName and pathes with the blacklist_msgName_path
    // Then, if they are the same, do std::getline(inputTestFile, line); again.
    // Also, update the curLineNum and curPos
    // If they are not the same, we need to revert the file pointer of the inputTestFile one line. 
    // To do this, we need to store the curPos and curLineNum before we do std::getline(inputTestFile, line);
    // Then, we can do inputTestFile.seekg(curPos) and curLineNum-- to revert the file pointer and curLineNum.

    // First, do std::getline(inputTestFile, line); and compare the msgName and pathes with the blacklist_msgName_path
    std::string line;
    std::string numbering, filepayload, msgName_and_paths;

    do {
      curPos = inputTestFile.tellg();
      std::getline(inputTestFile, line);
      curLineNum++;
      std::istringstream lineStream(line);

      std::getline(lineStream, numbering, ',');
      std::getline(lineStream, filepayload, ',');
      std::getline(lineStream, msgName_and_paths);

      srsran::console("Debug: curLine (%d), #%s, msgName_and_paths is %s\n and target blacklist is %s\n", (curLineNum - 1), numbering, msgName_and_paths.c_str(), blacklist_msgName_and_paths.c_str());
      m_logger.info("Debug: msgName_and_paths is %s\n and target blacklist is %s", msgName_and_paths.c_str(), blacklist_msgName_and_paths.c_str());
    } while (blacklist_msgName_and_paths == msgName_and_paths);

    srsran::console("Done with the while loop, curLineNum is %d", curLineNum);
    curLineNum--;
    inputTestFile.seekg(curPos);

  }

  void s1ap::log_timestamp(std::string& msgNum){
  // std::ofstream logfile("data.csv", std::ios::app);
  logfile.open(logfile_name, std::ios::app);

  auto now = std::chrono::system_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

  // Format the timestamp as a string
  std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
  struct std::tm* timeinfo = std::localtime(&timestamp);
  char timestampStr[64];
  std::strftime(timestampStr, sizeof(timestampStr), "%Y-%m-%d %H:%M:%S", timeinfo);


  if (logfile.is_open()){
    // logfile << msgNum << "," << std::ctime(&timestamp) << std::endl;  

    // Append data to the log file with the timestamp
    logfile << msgNum << "," << timestampStr << "." << std::setfill('0') << std::setw(3) << (ms % 1000) << std::endl;


    logfile.close();
  } else {
    m_logger.error("Failed to open the log file");
    srsran::console("Failed to open the log file\n");
  }
  
}


} // namespace srsepc
