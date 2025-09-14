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

#include "srsenb/hdr/stack/rrc/rrc.h"
#include "srsenb/hdr/stack/mac/sched_interface.h"
#include "srsenb/hdr/stack/rrc/rrc_cell_cfg.h"
#include "srsenb/hdr/stack/rrc/rrc_endc.h"
#include "srsenb/hdr/stack/rrc/rrc_mobility.h"
#include "srsenb/hdr/stack/rrc/rrc_paging.h"
#include "srsenb/hdr/stack/s1ap/s1ap.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/rrc_utils.h"
#include "srsran/common/bcd_helpers.h"
#include "srsran/common/enb_events.h"
#include "srsran/common/standard_streams.h"
#include "srsran/common/string_helpers.h"
#include "srsran/interfaces/enb_mac_interfaces.h"
#include "srsran/interfaces/enb_pdcp_interfaces.h"
#include "srsran/interfaces/enb_rlc_interfaces.h"

using srsran::byte_buffer_t;

using namespace asn1::rrc;

namespace srsenb {

rrc::rrc(srsran::task_sched_handle task_sched_, enb_bearer_manager& manager_) :
  logger(srslog::fetch_basic_logger("RRC")), bearer_manager(manager_), task_sched(task_sched_), rx_pdu_queue(128), maxSize(30), crashCounter(0), check_period(10)
{
}

rrc::~rrc() {}

int32_t rrc::init(const rrc_cfg_t&       cfg_,
                  phy_interface_rrc_lte* phy_,
                  mac_interface_rrc*     mac_,
                  rlc_interface_rrc*     rlc_,
                  pdcp_interface_rrc*    pdcp_,
                  s1ap_interface_rrc*    s1ap_,
                  gtpu_interface_rrc*    gtpu_)
{
  return init(cfg_, phy_, mac_, rlc_, pdcp_, s1ap_, gtpu_, nullptr);
}

int32_t rrc::init(const rrc_cfg_t&       cfg_,
                  phy_interface_rrc_lte* phy_,
                  mac_interface_rrc*     mac_,
                  rlc_interface_rrc*     rlc_,
                  pdcp_interface_rrc*    pdcp_,
                  s1ap_interface_rrc*    s1ap_,
                  gtpu_interface_rrc*    gtpu_,
                  rrc_nr_interface_rrc*  rrc_nr_)
{
  phy    = phy_;
  mac    = mac_;
  rlc    = rlc_;
  pdcp   = pdcp_;
  gtpu   = gtpu_;
  s1ap   = s1ap_;
  rrc_nr = rrc_nr_;

  cfg = cfg_;

  if (cfg.sibs[12].type() == asn1::rrc::sys_info_r8_ies_s::sib_type_and_info_item_c_::types::sib13_v920 &&
      cfg.enable_mbsfn) {
    configure_mbsfn_sibs();
  }

  cell_res_list.reset(new freq_res_common_list{cfg});

  // Loads the PRACH root sequence
  cfg.sibs[1].sib2().rr_cfg_common.prach_cfg.root_seq_idx = cfg.cell_list[0].root_seq_idx;

  if (cfg.num_nr_cells > 0) {
    cfg.sibs[1].sib2().ext = true;
    cfg.sibs[1].sib2().plmn_info_list_r15.set_present();
    cfg.sibs[1].sib2().plmn_info_list_r15.get()->resize(1);
    auto& plmn                       = cfg.sibs[1].sib2().plmn_info_list_r15.get()->back();
    plmn.upper_layer_ind_r15_present = true;
  }

  if (generate_sibs() != SRSRAN_SUCCESS) {
    logger.error("Couldn't generate SIBs.");
    return false;
  }
  config_mac();

  // Check valid inactivity timeout config
  uint32_t t310 = cfg.sibs[1].sib2().ue_timers_and_consts.t310.to_number();
  uint32_t t311 = cfg.sibs[1].sib2().ue_timers_and_consts.t311.to_number();
  uint32_t n310 = cfg.sibs[1].sib2().ue_timers_and_consts.n310.to_number();
  logger.info("T310 %d, T311 %d, N310 %d", t310, t311, n310);
  if (cfg.inactivity_timeout_ms < t310 + t311 + n310) {
    srsran::console("\nWarning: Inactivity timeout is smaller than the sum of t310, t311 and n310.\n"
                    "This may break the UE's re-establishment procedure.\n");
    logger.warning("Inactivity timeout is smaller than the sum of t310, t311 and n310. This may break the UE's "
                   "re-establishment procedure.");
  }
  logger.info("Inactivity timeout: %d ms", cfg.inactivity_timeout_ms);
  logger.info("Max consecutive MAC KOs: %d", cfg.max_mac_dl_kos);

  pending_paging.reset(new paging_manager(cfg.sibs[1].sib2().rr_cfg_common.pcch_cfg.default_paging_cycle.to_number(),
                                          cfg.sibs[1].sib2().rr_cfg_common.pcch_cfg.nb.to_number()));

  running = true;

  // Also add the reattach timer
  repaging_timer = task_sched.get_unique_timer();

  // Also add the NAS oracle timer
  nas_oracle_timer = task_sched.get_unique_timer();

  // Also add the RRC oracle timer
  rrc_oracle_timer = task_sched.get_unique_timer();


  // name the output logging path
  logging_path = cfg.output_directory_name;
  
  // name the logfile
  std::time_t now = std::time(nullptr);
  std::tm* localTime = std::localtime(&now);
  std::ostringstream filenameStream;
  filenameStream << logging_path << "_" << "data_" << std::put_time(localTime, "%y%m%d_%H%M%S") << ".csv";
  srsran::console("name of the logfile is %s\n", filenameStream.str().c_str());
  logfile_name = filenameStream.str();

  if (logger.debug.enabled()) {
    asn1::json_writer js{};
    cfg.srb1_cfg.rlc_cfg.to_json(js);
    logger.debug("SRB1 configuration: %s", js.to_string().c_str());
    js = {};
    cfg.srb2_cfg.rlc_cfg.to_json(js);
    logger.debug("SRB2 configuration: %s", js.to_string().c_str());
  }
  return SRSRAN_SUCCESS;
}

void rrc::stop()
{
  if (running) {
    running   = false;
    rrc_pdu p = {0, LCID_EXIT, false, nullptr};
    rx_pdu_queue.push_blocking(std::move(p));
  }
  users.clear();
}

/*******************************************************************************
  Timer related functions
*******************************************************************************/
bool rrc::set_reattach_timer()
{
  srsran::console("Set reattach timer\n");
  logger.info("Set reattach timer\n");
  auto timer_expire_func = [this](uint32_t tid) { reattach_timer_expired(tid); };
  
  uint32_t reattach_deadline_ms = 500; // 0.5 seconds 

  // If it's running
  stop_reattach_timer();

  repaging_timer.set(reattach_deadline_ms, timer_expire_func);
  repaging_timer.run();
  return true;
}

bool rrc::stop_reattach_timer()
{

  if (repaging_timer.is_running()){
      srsran::console("Stop reattach timer1\n");
      logger.info("Stop reattach timer1\n");
      repaging_timer.stop();
    }

  return true;
}

void rrc::reattach_timer_expired(uint32_t timeout_id)
{
  logger.info("Reattach timer expired\n");
  stop_reattach_timer();

  // auto user_it = users.find(recent_rnti);
  // if (user_it == users.end()) {
  //   logger.error("Unrecognised rnti=0x%x", recent_rnti);
  //   return;
  // }
  // srsran::console("Releasing rnti=0x%x", recent_rnti);
  // user_it->second->send_connection_release();
  // release_ue(recent_rnti);
  // user_it->second->send_dl_dcch_bytes("2802"); // This is not being sent to UE
  // logger.info("Releasing rnti=0x%x", recent_rnti);

  ++paging_attempt;
  
  if (paging_attempt >= 4){
    logger.info("Paging attempt is over 3 times, toggle airplane mode");
    srsran::console("Paging attempt is over 3 times, toggle airplane mode\n");

    // reattach_deadline is 0.5s. To wait 1 min, we need to wait 120 times.
    if (airplanemode_attempt >= 4){
      logger.info("Airplane mode attempt is over 3 times, wait for longer time, [%d/%d]", paging_attempt, airplane_mode_timer);
      srsran::console("Airplane mode attempt is over 3 times, wait for longer time, [%d/%d]\n", paging_attempt, airplane_mode_timer);
      if (paging_attempt >= airplane_mode_timer){
        toggle_airplane_mode(cfg.test_device.c_str());
        paging_attempt = 0;
        airplanemode_attempt = 0;
      } else if (paging_attempt == 10 || paging_attempt == 16 || paging_attempt == 30 || paging_attempt == 36){
        // toggle_airplane_mode((cfg.test_device.append("_single")).c_str());
        toggle_airplane_mode(cfg.test_device.c_str());
      }
    } else {
      toggle_airplane_mode(cfg.test_device.c_str());
      paging_attempt = 0;
    }
  }

  send_paging((uint64_t)901550000044693, cur_tmsi);
  set_reattach_timer();

}

bool rrc::set_nas_oracle_timer()
{
  srsran::console("Set nas oracle timer\n");
  logger.info("Set nas oracle timer\n");
  auto timer_expire_func = [this](uint32_t tid) { nas_oracle_timer_expired(tid); };
  
  uint32_t nas_oracle_deadline_ms = 1000; // 1 seconds 
  nas_oracle_timer.set(nas_oracle_deadline_ms, timer_expire_func);
  nas_oracle_timer.run();
  return true;
}

void rrc::nas_oracle_timer_expired(uint32_t timeout_id)
{
  logger.info("NAS oracle timer expired!\n");
  srsran::console("NAS oracle timer expired!\n");

  nas_oracle_timer.stop();

  // Disable sending msg now.
  // TODO: Should we?
  auto user_it = users.find(recent_rnti);

  if (user_it == users.end()) {
    logger.error("Unrecognised rnti=0x%x", recent_rnti);
    return;
  }
  user_it->second->ready_for_test = false;

  // Notify NAS that the oracle is expired. 
  s1ap->notify_nas_oracle(recent_rnti);

}

bool rrc::set_rrc_oracle_timer()
{
  srsran::console("Set rrc oracle timer\n");
  logger.info("Set rrc oracle timer\n");
  auto timer_expire_func = [this](uint32_t tid) { rrc_oracle_timer_expired(tid); };
  
  uint32_t rrc_oracle_deadline_ms = 1000; // 1 seconds 
  rrc_oracle_timer.set(rrc_oracle_deadline_ms, timer_expire_func);
  rrc_oracle_timer.run();
  return true;
}

void rrc::rrc_oracle_timer_expired(uint32_t timeout_id)
{
  logger.info("RRC oracle timer expired!\n");
  srsran::console("RRC oracle timer expired!\n");

  rrc_oracle_timer.stop();

  auto user_it = users.find(recent_rnti);

  if (user_it == users.end()) {
    logger.error("Unrecognised rnti=0x%x", recent_rnti);
    return;
  }
  user_it->second->ready_for_test = false;

  // Notify NAS that the oracle is expired. 
  user_it->second->notify_rrc_oracle();

}


/*******************************************************************************
  Public functions
*******************************************************************************/

void rrc::get_metrics(rrc_metrics_t& m)
{
  if (running) {
    m.ues.resize(users.size());
    size_t count = 0;
    for (auto& ue : users) {
      ue.second->get_metrics(m.ues[count++]);
    }
  }
}

/*******************************************************************************
  MAC interface

  Those functions that shall be called from a phch_worker should push the command
  to the queue and process later
*******************************************************************************/

uint8_t* rrc::read_pdu_bcch_dlsch(const uint8_t cc_idx, const uint32_t sib_index)
{
  if (sib_index < ASN1_RRC_MAX_SIB && cc_idx < cell_common_list->nof_cells()) {
    return cell_common_list->get_cc_idx(cc_idx)->sib_buffer.at(sib_index)->msg;
  }
  return nullptr;
}

void rrc::set_radiolink_dl_state(uint16_t rnti, bool crc_res)
{
  // embed parameters in arg value
  rrc_pdu p = {rnti, LCID_RADLINK_DL, crc_res, nullptr};

  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push radio link DL state");
  }
}

void rrc::set_radiolink_ul_state(uint16_t rnti, bool crc_res)
{
  // embed parameters in arg value
  rrc_pdu p = {rnti, LCID_RADLINK_UL, crc_res, nullptr};

  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push radio link UL state");
  }
}

void rrc::set_activity_user(uint16_t rnti)
{
  rrc_pdu p = {rnti, LCID_ACT_USER, false, nullptr};

  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push UE activity command to RRC queue");
  }
}

void rrc::rem_user_thread(uint16_t rnti)
{
  rrc_pdu p = {rnti, LCID_REM_USER, false, nullptr};
  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push UE remove command to RRC queue");
  }
}

uint32_t rrc::get_nof_users()
{
  return users.size();
}

void rrc::max_retx_attempted(uint16_t rnti)
{
  rrc_pdu p = {rnti, LCID_RLC_RTX, false, nullptr};
  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push max Retx event to RRC queue");
  }

  // Also, notify the ack_timeout oracle. 
  logger.info("Notify ack timeout oracle");

  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.error("Unrecognised rnti=0x%x", rnti);
    return;
  }

  if (user_it->second->oracle_enabled){
    user_it->second->notify_ack_timeout();
    // user_it->second->ready_for_test = false;
  }
}

void rrc::protocol_failure(uint16_t rnti)
{
  rrc_pdu p = {rnti, LCID_PROT_FAIL, false, nullptr};
  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push protocol failure to RRC queue");
  }
}

// When eNB reveive RLC ACK, RLC thread calls this function to send next RRC/NAS message. 
void rrc::send_next_test_msg(uint16_t rnti)
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.error("Unrecognised rnti=0x%x", rnti);
    return;
  }

  user_it->second->oracle_enabled = true;
  // 1. Prevents to send the test message during state transition
  // 2. Allow message to be sent after checking oracle (if oracle fires, not allowing the next message)
  // if (!user_it->second->allow_next_msg) {
  //   logger.warning("Not allowed to send the next message, waiting for state transition\n");
  //   return;
  // }

  if (user_it->second->ready_for_test){
    if (repaging_timer.is_running()){
      srsran::console("Stop reattach timer1\n");
      logger.info("Stop reattach timer1\n");
      repaging_timer.stop();
    }
    set_reattach_timer();
    paging_attempt = 0;
    airplanemode_attempt = 0;

    if (cfg.target_protocol == TEST_RRC) {
      logger.info("Sending RRC message!\n");
      
      // Check if the replay mode is enabled
      if (cfg.replay_mode){
        srsran::console("Turn on the replay mode\n");
        user_it->second->send_rrc_test_message();
      } else {
        if (!is_backtracking){
          user_it->second->send_rrc_test_message();
        } else {
          user_it->second->send_rrc_test_message_backtracking();
        }
      }
      
      // user_it->second->send_rrc_test_message();
    } else if (cfg.target_protocol == TEST_NAS){
      // NAS FUZZING
      // send_nas_test_message is for sending NAS message
      // When we send the next msg at ID Response, the below is used for sending ID Request.
      // This part will be remained.
      logger.info("Seding NAS message!\n");
      user_it->second->send_nas_test_message();  // This sends NAS messages
    } else {
    srsran::console("Not supported \n");
    }
  } else{
    logger.warning("Not ready for test, waiting for state transition\n");
  }

}

// This function is called from PRACH worker (can wait)
int rrc::add_user(uint16_t rnti, const sched_interface::ue_cfg_t& sched_ue_cfg)
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    if (rnti != SRSRAN_MRNTI) {
      // only non-eMBMS RNTIs are present in user map
      unique_rnti_ptr<ue> u = make_rnti_obj<ue>(rnti, this, rnti, sched_ue_cfg);
      if (u->init() != SRSRAN_SUCCESS) {
        logger.error("Adding user rnti=0x%x - Failed to allocate user resources", rnti);
        return SRSRAN_ERROR;
      }
      users.insert(std::make_pair(rnti, std::move(u)));
    }
    rlc->add_user(rnti);
    pdcp->add_user(rnti);
    logger.info("Added new user rnti=0x%x", rnti);
  } else {
    logger.error("Adding user rnti=0x%x (already exists)", rnti);
  }

  if (rnti == SRSRAN_MRNTI) {
    for (auto& mbms_item : mcch.msg.c1().mbsfn_area_cfg_r9().pmch_info_list_r9[0].mbms_session_info_list_r9) {
      uint32_t lcid = mbms_item.lc_ch_id_r9;
      uint32_t addr_in;
      // adding UE object to MAC for MRNTI without scheduling configuration (broadcast not part of regular scheduling)
      rlc->add_bearer_mrb(SRSRAN_MRNTI, lcid);
      bearer_manager.add_eps_bearer(SRSRAN_MRNTI, 1, srsran::srsran_rat_t::lte, lcid);
      pdcp->add_bearer(SRSRAN_MRNTI, lcid, srsran::make_drb_pdcp_config_t(1, false));
      gtpu->add_bearer(SRSRAN_MRNTI, lcid, 1, 1, addr_in);
    }
  }
  return SRSRAN_SUCCESS;
}

/* Function called by MAC after the reception of a C-RNTI CE indicating that the UE still has a
 * valid RNTI.
 */
void rrc::upd_user(uint16_t new_rnti, uint16_t old_rnti)
{
  // Remove new_rnti
  auto new_ue_it = users.find(new_rnti);
  if (new_ue_it != users.end()) {
    new_ue_it->second->deactivate_bearers();
    rem_user_thread(new_rnti);
  }

  // Send Reconfiguration to old_rnti if is RRC_CONNECT or RRC Release if already released here
  auto old_it = users.find(old_rnti);
  if (old_it == users.end()) {
    logger.info("rnti=0x%x received MAC CRNTI CE: 0x%x, but old context is unavailable", new_rnti, old_rnti);
    return;
  }
  ue* ue_ptr = old_it->second.get();

  if (ue_ptr->mobility_handler->is_ho_running()) {
    ue_ptr->mobility_handler->trigger(ue::rrc_mobility::user_crnti_upd_ev{old_rnti, new_rnti});
  } else {
    logger.info("Resuming rnti=0x%x RRC connection due to received C-RNTI CE from rnti=0x%x.", old_rnti, new_rnti);
    if (ue_ptr->is_connected()) {
      // Send a new RRC Reconfiguration to overlay previous
      old_it->second->send_connection_reconf();
    }
  }

  // Log event.
  event_logger::get().log_connection_resume(
      ue_ptr->get_cell_list().get_ue_cc_idx(UE_PCELL_CC_IDX)->cell_common->enb_cc_idx, old_rnti, new_rnti);
}

// Note: this method is not part of UE methods, because the UE context may not exist anymore when reject is sent
void rrc::send_rrc_connection_reject(uint16_t rnti)
{
  dl_ccch_msg_s dl_ccch_msg;
  dl_ccch_msg.msg.set_c1().set_rrc_conn_reject().crit_exts.set_c1().set_rrc_conn_reject_r8().wait_time = 10;

  // Allocate a new PDU buffer, pack the message and send to PDCP
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    logger.error("Allocating pdu");
    return;
  }
  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  if (dl_ccch_msg.pack(bref) != asn1::SRSASN_SUCCESS) {
    logger.error(pdu->msg, bref.distance_bytes(), "Failed to pack DL-CCCH-Msg:");
    return;
  }
  pdu->N_bytes = bref.distance_bytes();

  log_rrc_message(Tx, rnti, srb_to_lcid(lte_srb::srb0), *pdu, dl_ccch_msg, dl_ccch_msg.msg.c1().type().to_string());

  rlc->write_sdu(rnti, srb_to_lcid(lte_srb::srb0), std::move(pdu));
}

/*******************************************************************************
  PDCP interface
*******************************************************************************/
void rrc::write_pdu(uint16_t rnti, uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
  rrc_pdu p = {rnti, lcid, false, std::move(pdu)};
  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push Release command to RRC queue");
  }
}

void rrc::notify_pdcp_integrity_error(uint16_t rnti, uint32_t lcid)
{
  logger.warning("Received integrity protection failure indication, rnti=0x%x, lcid=%u", rnti, lcid);
  s1ap->user_release(rnti, asn1::s1ap::cause_radio_network_opts::unspecified);
}

/*******************************************************************************
  S1AP interface
*******************************************************************************/
void rrc::write_dl_info(uint16_t rnti, srsran::unique_byte_buffer_t sdu, bool is_id_req)
{
  dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1();
  dl_dcch_msg_type_c::c1_c_* msg_c1 = &dl_dcch_msg.msg.c1();

  auto user_it = users.find(rnti);
  if (user_it != users.end()) {

    // when we are sending ID Req for liveness check, 
    // enable waiting_for_nas_oracle, to handle the ID response specially, and
    // disable ready_for_test, to avoid sending ID Req again due to the RLC ACK. 
    // We will request NAS msg after checking ID Req. 
    if (cfg.target_protocol == TEST_NAS && user_it->second->ready_for_test && is_id_req){
      user_it->second->waiting_for_nas_oracle = true;
      user_it->second->ready_for_test = false;

      // set nas oracle timer
      set_nas_oracle_timer();
    } else if (cfg.target_protocol == TEST_NAS && user_it->second->waiting_for_nas_oracle && is_id_req){
      // When sending NAS oracle several times while not receiving ID response
      set_nas_oracle_timer();
    }


    dl_info_transfer_r8_ies_s* dl_info_r8 =
        &msg_c1->set_dl_info_transfer().crit_exts.set_c1().set_dl_info_transfer_r8();
    //    msg_c1->dl_info_transfer().rrc_transaction_id = ;
    dl_info_r8->non_crit_ext_present = false;
    dl_info_r8->ded_info_type.set_ded_info_nas();
    dl_info_r8->ded_info_type.ded_info_nas().resize(sdu->N_bytes);
    memcpy(msg_c1->dl_info_transfer().crit_exts.c1().dl_info_transfer_r8().ded_info_type.ded_info_nas().data(),
           sdu->msg,
           sdu->N_bytes);

    sdu->clear();

    user_it->second->send_dl_dcch(&dl_dcch_msg, std::move(sdu));

    // When sending something, set the reattach timer, and stop it when there is ul_dcch response
    set_reattach_timer();

  } else {
    logger.error("Rx SDU for unknown rnti=0x%x", rnti);
  }
}

void rrc::release_ue(uint16_t rnti)
{
  rrc_pdu p = {rnti, LCID_REL_USER, false, nullptr};
  if (not rx_pdu_queue.try_push(std::move(p))) {
    logger.error("Failed to push Release command to RRC queue");
  }
}

bool rrc::setup_ue_ctxt(uint16_t rnti, const asn1::s1ap::init_context_setup_request_s& msg)
{
  logger.info("Adding initial context for 0x%x", rnti);
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }

  user_it->second->handle_ue_init_ctxt_setup_req(msg);
  return true;
}

bool rrc::modify_ue_ctxt(uint16_t rnti, const asn1::s1ap::ue_context_mod_request_s& msg)
{
  logger.info("Modifying context for 0x%x", rnti);
  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }

  return user_it->second->handle_ue_ctxt_mod_req(msg);
}

bool rrc::release_erabs(uint32_t rnti)
{
  logger.info("Releasing E-RABs for 0x%x", rnti);
  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }

  bool ret = user_it->second->release_erabs();
  return ret;
}

int rrc::release_erab(uint16_t rnti, uint16_t erab_id)
{
  logger.info("Releasing E-RAB id=%d for 0x%x", erab_id, rnti);
  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return SRSRAN_ERROR;
  }

  return user_it->second->release_erab(erab_id);
}

void rrc::send_connection_release_tau(uint16_t rnti)
{
  logger.info("Releasing RRC connection and requesting TAU for 0x%x", rnti);
  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return;
  }

  return user_it->second->send_connection_release_tau();
}

void rrc::send_connection_release_other(uint16_t rnti)
{
  logger.info("Releasing RRC connection for 0x%x", rnti);
  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return;
  }

  return user_it->second->send_connection_release();
}

bool rrc::set_ready_for_test(uint16_t rnti, bool is_ready_for_test)
{
  logger.info("Setting ready for test for 0x%x", rnti);
  
  // log setting ready for test for rnti with boolean is_ready_for_test
  logger.info("Setting ready for test for 0x%x, bool: %s", rnti, is_ready_for_test ? "true":"false");

  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }

  user_it->second->ready_for_test = is_ready_for_test;

  return true;
}

bool rrc::set_reattach_timeout(uint16_t rnti, bool run_the_timer){
    
  // log setting reattach timer for rnti
  logger.info("Setting reattach timeout for 0x%x, bool: %s", rnti, run_the_timer ? "on":"off");

  auto user_it = users.find(rnti);

  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }
  if (run_the_timer){
    user_it->second->set_reattach_timeout();
  } else {
    // user_it->second->activity_timer.stop();
  }

  return true;
}

int rrc::notify_ue_erab_updates(uint16_t rnti, srsran::const_byte_span nas_pdu)
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return SRSRAN_ERROR;
  }
  user_it->second->send_connection_reconf(nullptr, false, nas_pdu);
  return SRSRAN_SUCCESS;
}

bool rrc::has_erab(uint16_t rnti, uint32_t erab_id) const
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return false;
  }
  return user_it->second->has_erab(erab_id);
}

int rrc::get_erab_addr_in(uint16_t rnti, uint16_t erab_id, transp_addr_t& addr_in, uint32_t& teid_in) const
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return SRSRAN_ERROR;
  }
  return user_it->second->get_erab_addr_in(erab_id, addr_in, teid_in);
}

void rrc::set_aggregate_max_bitrate(uint16_t rnti, const asn1::s1ap::ue_aggregate_maximum_bitrate_s& bitrate)
{
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    return;
  }
  user_it->second->set_bitrates(bitrate);
}

int rrc::setup_erab(uint16_t                                           rnti,
                    uint16_t                                           erab_id,
                    const asn1::s1ap::erab_level_qos_params_s&         qos_params,
                    srsran::const_span<uint8_t>                        nas_pdu,
                    const asn1::bounded_bitstring<1, 160, true, true>& addr,
                    uint32_t                                           gtpu_teid_out,
                    asn1::s1ap::cause_c&                               cause)
{
  logger.info("Setting up erab id=%d for 0x%x", erab_id, rnti);
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    cause.set_radio_network().value = asn1::s1ap::cause_radio_network_opts::unknown_erab_id;
    return SRSRAN_ERROR;
  }
  return user_it->second->setup_erab(erab_id, qos_params, nas_pdu, addr, gtpu_teid_out, cause);
}

int rrc::modify_erab(uint16_t                                   rnti,
                     uint16_t                                   erab_id,
                     const asn1::s1ap::erab_level_qos_params_s& qos_params,
                     srsran::const_span<uint8_t>                nas_pdu,
                     asn1::s1ap::cause_c&                       cause)
{
  logger.info("Modifying E-RAB for 0x%x. E-RAB Id %d", rnti, erab_id);
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.warning("Unrecognised rnti: 0x%x", rnti);
    cause.set_radio_network().value = asn1::s1ap::cause_radio_network_opts::unknown_erab_id;
    return SRSRAN_ERROR;
  }

  return user_it->second->modify_erab(erab_id, qos_params, nas_pdu, cause);
}

/*******************************************************************************
  Paging functions
  These functions use a different mutex because access different shared variables
  than user map
*******************************************************************************/

void rrc::add_paging_id(uint32_t ueid, const asn1::s1ap::ue_paging_id_c& ue_paging_id)
{
  if (ue_paging_id.type().value == asn1::s1ap::ue_paging_id_c::types_opts::imsi) {
    pending_paging->add_imsi_paging(ueid, ue_paging_id.imsi());
  } else {
    pending_paging->add_tmsi_paging(ueid, ue_paging_id.s_tmsi().mmec[0], ue_paging_id.s_tmsi().m_tmsi);
  }
}

void rrc::send_paging(uint64_t imsi, uint32_t tmsi){

  if (imsi != 0){
    // uint64_t imsi = 901550000044693;
    uint16_t ue_index = imsi % 1024;
    srsran::console("UE index: %d\n", ue_index);

    asn1::s1ap::ue_paging_id_c ue_paging_id_c;
    ue_paging_id_c.set_imsi();
    ue_paging_id_c.imsi().from_number(imsi);

    ue_paging_id_c.imsi().resize(15);

    for (int i = 15 - 1; i >= 0; i--){
      ue_paging_id_c.imsi()[i] = imsi % 10;
      imsi /= 10;
    }

    add_paging_id(ue_index, ue_paging_id_c);
    // print to console
    srsran::console("Paging sent to UE with IMSI %lu\n", imsi);
  }

  if (tmsi != 0){
    uint16_t ue_index = (uint64_t)901550000044693 % 1024;
    srsran::console("UE index: %d\n", ue_index);

    asn1::s1ap::ue_paging_id_c ue_paging_id_c;
    ue_paging_id_c.set_s_tmsi();
    ue_paging_id_c.s_tmsi().mmec.from_number(0x1a);
    ue_paging_id_c.s_tmsi().m_tmsi.from_number(tmsi);
    // ue_paging_id_c.s_tmsi().mmec[0] = 0x00;
    // ue_paging_id_c.s_tmsi().m_tmsi = tmsi;

    add_paging_id(ue_index, ue_paging_id_c);
    //print to console
    srsran::console("Paging sent to UE with TMSI %lu\n", tmsi);
  }
  

  //
  // for (int i=0; i<1024; i++){
  //   add_paging_id(i, ue_paging_id_c);
  // }
  //

  // srsran::console("Paging sent to UE with IMSI %lu\n", imsi);
}


bool rrc::is_paging_opportunity(uint32_t tti, uint32_t* payload_len)
{
  *payload_len = pending_paging->pending_pcch_bytes(tti_point(tti));
  return *payload_len > 0;
}

void rrc::read_pdu_pcch(uint32_t tti_tx_dl, uint8_t* payload, uint32_t buffer_size)
{
  auto read_func = [this, payload, buffer_size](srsran::const_byte_span pdu, const pcch_msg_s& msg, bool first_tx) {
    // copy PCCH pdu to buffer
    if (pdu.size() > buffer_size) {
      logger.warning("byte buffer with size=%zd is too small to fit pcch msg with size=%zd", buffer_size, pdu.size());
      return false;
    }
    std::copy(pdu.begin(), pdu.end(), payload);

    if (first_tx) {
      logger.info("Assembling PCCH payload with %d UE identities, payload_len=%d bytes",
                  msg.msg.c1().paging().paging_record_list.size(),
                  pdu.size());
      log_broadcast_rrc_message(SRSRAN_PRNTI, pdu, msg, msg.msg.c1().type().to_string());
    }
    return true;
  };

  pending_paging->read_pdu_pcch(tti_point(tti_tx_dl), read_func);
}

/*******************************************************************************
  Handover functions
*******************************************************************************/

void rrc::ho_preparation_complete(uint16_t                     rnti,
                                  ho_prep_result               result,
                                  const asn1::s1ap::ho_cmd_s&  msg,
                                  srsran::unique_byte_buffer_t rrc_container)
{
  users.at(rnti)->mobility_handler->handle_ho_preparation_complete(result, msg, std::move(rrc_container));
}

void rrc::set_erab_status(uint16_t rnti, const asn1::s1ap::bearers_subject_to_status_transfer_list_l& erabs)
{
  auto ue_it = users.find(rnti);
  if (ue_it == users.end()) {
    logger.warning("rnti=0x%x does not exist", rnti);
    return;
  }
  ue_it->second->mobility_handler->trigger(erabs);
}

/*******************************************************************************
  EN-DC/NSA helper functions
*******************************************************************************/

void rrc::sgnb_addition_ack(uint16_t eutra_rnti, sgnb_addition_ack_params_t params)
{
  logger.info("Received SgNB addition acknowledgement for rnti=0x%x", eutra_rnti);
  auto ue_it = users.find(eutra_rnti);
  if (ue_it == users.end()) {
    logger.warning("rnti=0x%x does not exist", eutra_rnti);
    return;
  }
  ue_it->second->endc_handler->trigger(ue::rrc_endc::sgnb_add_req_ack_ev{params});

  // trigger RRC Reconfiguration to send NR config to UE
  ue_it->second->send_connection_reconf();
}

void rrc::sgnb_addition_reject(uint16_t eutra_rnti)
{
  logger.error("Received SgNB addition reject for rnti=%d", eutra_rnti);
  auto ue_it = users.find(eutra_rnti);
  if (ue_it == users.end()) {
    logger.warning("rnti=0x%x does not exist", eutra_rnti);
    return;
  }
  ue_it->second->endc_handler->trigger(ue::rrc_endc::sgnb_add_req_reject_ev{});
}

void rrc::sgnb_addition_complete(uint16_t eutra_rnti, uint16_t nr_rnti)
{
  logger.info("User rnti=0x%x successfully enabled EN-DC", eutra_rnti);
  auto ue_it = users.find(eutra_rnti);
  if (ue_it == users.end()) {
    logger.warning("rnti=0x%x does not exist", eutra_rnti);
    return;
  }
  ue_it->second->endc_handler->trigger(ue::rrc_endc::sgnb_add_complete_ev{nr_rnti});
}

void rrc::sgnb_inactivity_timeout(uint16_t eutra_rnti)
{
  logger.info("Received NR inactivity timeout for rnti=0x%x - releasing UE", eutra_rnti);
  auto ue_it = users.find(eutra_rnti);
  if (ue_it == users.end()) {
    logger.warning("rnti=0x%x does not exist", eutra_rnti);
    return;
  }
  s1ap->user_release(eutra_rnti, asn1::s1ap::cause_radio_network_opts::user_inactivity);
}

void rrc::sgnb_release_ack(uint16_t eutra_rnti)
{
  auto ue_it = users.find(eutra_rnti);
  if (ue_it != users.end()) {
    logger.info("Received SgNB release acknowledgement for rnti=0x%x", eutra_rnti);
    ue_it->second->endc_handler->trigger(ue::rrc_endc::sgnb_rel_req_ack_ev{});
  } else {
    // The EUTRA does not need to wait for Release Ack in case it wants to destroy the EUTRA UE
    logger.info("Received SgNB release acknowledgement for already released rnti=0x%x", eutra_rnti);
  }
}

/*******************************************************************************
  Private functions
  All private functions are not mutexed and must be called from a mutexed environment
  from either a public function or the internal thread
*******************************************************************************/

void rrc::parse_ul_ccch(ue& ue, srsran::unique_byte_buffer_t pdu)
{
  srsran_assert(pdu != nullptr, "handle_ul_ccch called for empty message");

  ul_ccch_msg_s  ul_ccch_msg;
  asn1::cbit_ref bref(pdu->msg, pdu->N_bytes);
  if (ul_ccch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
      ul_ccch_msg.msg.type().value != ul_ccch_msg_type_c::types_opts::c1) {
    log_rx_pdu_fail(ue.rnti, srb_to_lcid(lte_srb::srb0), *pdu, "Failed to unpack UL-CCCH message");
    return;
  }

  // Log Rx message
  log_rrc_message(
      Rx, ue.rnti, srsran::srb_to_lcid(lte_srb::srb0), *pdu, ul_ccch_msg, ul_ccch_msg.msg.c1().type().to_string());

  switch (ul_ccch_msg.msg.c1().type().value) {
    case ul_ccch_msg_type_c::c1_c_::types::rrc_conn_request:
      ue.save_ul_message(std::move(pdu));
      ue.handle_rrc_con_req(&ul_ccch_msg.msg.c1().rrc_conn_request());
      break;
    case ul_ccch_msg_type_c::c1_c_::types::rrc_conn_reest_request:
      ue.save_ul_message(std::move(pdu));
      if (cfg.target_protocol == TEST_RRC){
        if (is_backtracking){
          is_backtracking = false;
          backtracking_num = 0;
          backtracking_num_total = 0;
          backtracking_msg = "";
        }
      }
      ue.handle_rrc_con_reest_req(&ul_ccch_msg.msg.c1().rrc_conn_reest_request());
      break;
    default:
      logger.error("Processing UL-CCCH for rnti=0x%x - Unsupported message type %s",
                   ul_ccch_msg.msg.c1().type().to_string());
      break;
  }
}

///< User mutex must be hold by caller
void rrc::parse_ul_dcch(ue& ue, uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
  srsran_assert(pdu != nullptr, "handle_ul_dcch called for empty message");

  ue.parse_ul_dcch(lcid, std::move(pdu));
}

///< User mutex must be hold by caller
void rrc::process_release_complete(uint16_t rnti)
{
  logger.info("Received Release Complete rnti=0x%x", rnti);
  auto user_it = users.find(rnti);
  if (user_it == users.end()) {
    logger.error("Received ReleaseComplete for unknown rnti=0x%x", rnti);
    return;
  }
  ue* u = user_it->second.get();

  if (u->is_idle() or u->mobility_handler->is_ho_running()) {
    rem_user_thread(rnti);
  } else if (not u->is_idle()) {
    rlc->clear_buffer(rnti);
    user_it->second->send_connection_release();
    // delay user deletion for ~50 TTI (until RRC release is sent)
    task_sched.defer_callback(50, [this, rnti]() { rem_user_thread(rnti); });
  }
}

void rrc::rem_user(uint16_t rnti)
{
  auto user_it = users.find(rnti);
  if (user_it != users.end()) {
    // First remove MAC and GTPU to stop processing DL/UL traffic for this user
    mac->ue_rem(rnti); // MAC handles PHY
    gtpu->rem_user(rnti);

    // Now remove RLC and PDCP
    bearer_manager.rem_user(rnti);
    rlc->rem_user(rnti);
    pdcp->rem_user(rnti);

    users.erase(rnti);

    srsran::console("Disconnecting rnti=0x%x.\n", rnti);
    logger.info("Removed user rnti=0x%x", rnti);
  } else {
    logger.error("Removing user rnti=0x%x (does not exist)", rnti);
  }
}

void rrc::config_mac()
{
  using sched_cell_t = sched_interface::cell_cfg_t;

  // Fill MAC scheduler configuration for SIBs
  std::vector<sched_cell_t> sched_cfg;
  sched_cfg.resize(cfg.cell_list.size());

  for (uint32_t ccidx = 0; ccidx < cfg.cell_list.size(); ++ccidx) {
    sched_interface::cell_cfg_t& item = sched_cfg[ccidx];

    // set sib/prach cfg
    for (uint32_t i = 0; i < nof_si_messages; i++) {
      item.sibs[i].len = cell_common_list->get_cc_idx(ccidx)->sib_buffer.at(i)->N_bytes;
      if (i == 0) {
        item.sibs[i].period_rf = 8; // SIB1 is always 8 rf
      } else {
        item.sibs[i].period_rf = cfg.sib1.sched_info_list[i - 1].si_periodicity.to_number();
      }
    }
    item.prach_config        = cfg.sibs[1].sib2().rr_cfg_common.prach_cfg.prach_cfg_info.prach_cfg_idx;
    item.prach_nof_preambles = cfg.sibs[1].sib2().rr_cfg_common.rach_cfg_common.preamb_info.nof_ra_preambs.to_number();
    item.si_window_ms        = cfg.sib1.si_win_len.to_number();
    item.prach_rar_window =
        cfg.sibs[1].sib2().rr_cfg_common.rach_cfg_common.ra_supervision_info.ra_resp_win_size.to_number();
    item.prach_freq_offset    = cfg.sibs[1].sib2().rr_cfg_common.prach_cfg.prach_cfg_info.prach_freq_offset;
    item.maxharq_msg3tx       = cfg.sibs[1].sib2().rr_cfg_common.rach_cfg_common.max_harq_msg3_tx;
    item.enable_64qam         = cfg.sibs[1].sib2().rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.enable64_qam;
    item.target_pucch_ul_sinr = cfg.cell_list[ccidx].target_pucch_sinr_db;
    item.target_pusch_ul_sinr = cfg.cell_list[ccidx].target_pusch_sinr_db;
    item.enable_phr_handling  = cfg.cell_list[ccidx].enable_phr_handling;
    item.min_phr_thres        = cfg.cell_list[ccidx].min_phr_thres;
    item.delta_pucch_shift    = cfg.sibs[1].sib2().rr_cfg_common.pucch_cfg_common.delta_pucch_shift.to_number();
    item.ncs_an               = cfg.sibs[1].sib2().rr_cfg_common.pucch_cfg_common.ncs_an;
    item.n1pucch_an           = cfg.sibs[1].sib2().rr_cfg_common.pucch_cfg_common.n1_pucch_an;
    item.nrb_cqi              = cfg.sibs[1].sib2().rr_cfg_common.pucch_cfg_common.nrb_cqi;

    item.nrb_pucch = SRSRAN_MAX(cfg.sr_cfg.nof_prb, item.nrb_cqi);
    logger.info("Allocating %d PRBs for PUCCH", item.nrb_pucch);

    // Copy base cell configuration
    item.cell    = cfg.cell;
    item.cell.id = cfg.cell_list[ccidx].pci;

    // copy secondary cell list info
    sched_cfg[ccidx].scell_list.reserve(cfg.cell_list[ccidx].scell_list.size());
    for (uint32_t scidx = 0; scidx < cfg.cell_list[ccidx].scell_list.size(); ++scidx) {
      const auto& scellitem = cfg.cell_list[ccidx].scell_list[scidx];
      // search enb_cc_idx specific to cell_id
      auto it = std::find_if(cfg.cell_list.begin(), cfg.cell_list.end(), [&scellitem](const cell_cfg_t& e) {
        return e.cell_id == scellitem.cell_id;
      });
      if (it == cfg.cell_list.end()) {
        logger.warning("Secondary cell 0x%x not configured", scellitem.cell_id);
        continue;
      }
      sched_interface::cell_cfg_t::scell_cfg_t scellcfg;
      scellcfg.enb_cc_idx               = it - cfg.cell_list.begin();
      scellcfg.ul_allowed               = scellitem.ul_allowed;
      scellcfg.cross_carrier_scheduling = scellitem.cross_carrier_sched;
      sched_cfg[ccidx].scell_list.push_back(scellcfg);
    }
  }

  // Configure MAC scheduler
  mac->cell_cfg(sched_cfg);
}

/* This methods packs the SIBs for each component carrier and stores them
 * inside the sib_buffer, a vector of SIBs for each CC.
 *
 * Before packing the message, it patches the cell specific params of
 * the SIB, including the cellId and the PRACH config index.
 *
 * The number of generates SIB messages is stored in the class member nof_si_messages
 *
 * @return SRSRAN_SUCCESS on success, SRSRAN_ERROR on failure
 */
uint32_t rrc::generate_sibs()
{
  // nof_messages includes SIB2 by default, plus all configured SIBs
  uint32_t           nof_messages = 1 + cfg.sib1.sched_info_list.size();
  sched_info_list_l& sched_info   = cfg.sib1.sched_info_list;

  // Store configs,SIBs in common cell ctxt list
  cell_common_list.reset(new enb_cell_common_list{cfg});

  // generate and pack into SIB buffers
  for (uint32_t cc_idx = 0; cc_idx < cfg.cell_list.size(); cc_idx++) {
    enb_cell_common* cell_ctxt = cell_common_list->get_cc_idx(cc_idx);
    // msg is array of SI messages, each SI message msg[i] may contain multiple SIBs
    // all SIBs in a SI message msg[i] share the same periodicity
    asn1::dyn_array<bcch_dl_sch_msg_s> msg(nof_messages + 1);

    // Copy SIB1 to first SI message
    msg[0].msg.set_c1().set_sib_type1() = cell_ctxt->sib1;

    // Copy rest of SIBs
    for (uint32_t sched_info_elem = 0; sched_info_elem < nof_messages - 1; sched_info_elem++) {
      uint32_t msg_index = sched_info_elem + 1; // first msg is SIB1, therefore start with second

      msg[msg_index].msg.set_c1().set_sys_info().crit_exts.set_sys_info_r8();
      sys_info_r8_ies_s::sib_type_and_info_l_& sib_list =
          msg[msg_index].msg.c1().sys_info().crit_exts.sys_info_r8().sib_type_and_info;

      // SIB2 always in second SI message
      if (msg_index == 1) {
        sib_info_item_c sibitem;
        sibitem.set_sib2() = cell_ctxt->sib2;
        sib_list.push_back(sibitem);
      }

      // Add other SIBs to this message, if any
      for (auto& mapping_enum : sched_info[sched_info_elem].sib_map_info) {
        sib_list.push_back(cfg.sibs[(int)mapping_enum + 2]);
      }
    }

    // Pack payload for all messages
    for (uint32_t msg_index = 0; msg_index < nof_messages; msg_index++) {
      srsran::unique_byte_buffer_t sib_buffer = srsran::make_byte_buffer();
      if (sib_buffer == nullptr) {
        logger.error("Couldn't allocate PDU in %s().", __FUNCTION__);
        return SRSRAN_ERROR;
      }
      asn1::bit_ref bref(sib_buffer->msg, sib_buffer->get_tailroom());
      if (msg[msg_index].pack(bref) != asn1::SRSASN_SUCCESS) {
        logger.error("Failed to pack SIB message %d", msg_index);
        return SRSRAN_ERROR;
      }
      sib_buffer->N_bytes = bref.distance_bytes();
      cell_ctxt->sib_buffer.push_back(std::move(sib_buffer));

      // Log SIBs in JSON format
      fmt::memory_buffer membuf;
      const char*        msg_str = msg[msg_index].msg.c1().type().to_string();
      if (msg[msg_index].msg.c1().type().value != asn1::rrc::bcch_dl_sch_msg_type_c::c1_c_::types_opts::sib_type1) {
        msg_str = msg[msg_index].msg.c1().sys_info().crit_exts.type().to_string();
      }
      fmt::format_to(membuf, "{}, cc={}, idx={}", msg_str, cc_idx, msg_index);
      log_broadcast_rrc_message(SRSRAN_SIRNTI, *cell_ctxt->sib_buffer.back(), msg[msg_index], srsran::to_c_str(membuf));
    }

    if (cfg.sibs[6].type() == asn1::rrc::sys_info_r8_ies_s::sib_type_and_info_item_c_::types::sib7) {
      sib7 = cfg.sibs[6].sib7();
    }
  }

  nof_si_messages = nof_messages;

  return SRSRAN_SUCCESS;
}

void rrc::configure_mbsfn_sibs()
{
  // populate struct with sib2 values needed in PHY/MAC
  srsran::sib2_mbms_t sibs2;
  sibs2.mbsfn_sf_cfg_list_present = cfg.sibs[1].sib2().mbsfn_sf_cfg_list_present;
  sibs2.nof_mbsfn_sf_cfg          = cfg.sibs[1].sib2().mbsfn_sf_cfg_list.size();
  for (int i = 0; i < sibs2.nof_mbsfn_sf_cfg; i++) {
    sibs2.mbsfn_sf_cfg_list[i].nof_alloc_subfrs = srsran::mbsfn_sf_cfg_t::sf_alloc_type_t::one_frame;
    sibs2.mbsfn_sf_cfg_list[i].radioframe_alloc_offset =
        cfg.sibs[1].sib2().mbsfn_sf_cfg_list[i].radioframe_alloc_offset;
    sibs2.mbsfn_sf_cfg_list[i].radioframe_alloc_period =
        (srsran::mbsfn_sf_cfg_t::alloc_period_t)cfg.sibs[1].sib2().mbsfn_sf_cfg_list[i].radioframe_alloc_period.value;
    sibs2.mbsfn_sf_cfg_list[i].sf_alloc =
        (uint32_t)cfg.sibs[1].sib2().mbsfn_sf_cfg_list[i].sf_alloc.one_frame().to_number();
  }
  // populate struct with sib13 values needed for PHY/MAC
  srsran::sib13_t sibs13;
  sibs13.notif_cfg.notif_offset = cfg.sibs[12].sib13_v920().notif_cfg_r9.notif_offset_r9;
  sibs13.notif_cfg.notif_repeat_coeff =
      (srsran::mbms_notif_cfg_t::coeff_t)cfg.sibs[12].sib13_v920().notif_cfg_r9.notif_repeat_coeff_r9.value;
  sibs13.notif_cfg.notif_sf_idx = cfg.sibs[12].sib13_v920().notif_cfg_r9.notif_sf_idx_r9;
  sibs13.nof_mbsfn_area_info    = cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9.size();
  for (uint32_t i = 0; i < sibs13.nof_mbsfn_area_info; i++) {
    sibs13.mbsfn_area_info_list[i].mbsfn_area_id =
        cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9[i].mbsfn_area_id_r9;
    sibs13.mbsfn_area_info_list[i].notif_ind        = cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9[i].notif_ind_r9;
    sibs13.mbsfn_area_info_list[i].mcch_cfg.sig_mcs = (srsran::mbsfn_area_info_t::mcch_cfg_t::sig_mcs_t)cfg.sibs[12]
                                                          .sib13_v920()
                                                          .mbsfn_area_info_list_r9[i]
                                                          .mcch_cfg_r9.sig_mcs_r9.value;
    sibs13.mbsfn_area_info_list[i].mcch_cfg.sf_alloc_info =
        cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9[i].mcch_cfg_r9.sf_alloc_info_r9.to_number();
    sibs13.mbsfn_area_info_list[i].mcch_cfg.mcch_repeat_period =
        (srsran::mbsfn_area_info_t::mcch_cfg_t::repeat_period_t)cfg.sibs[12]
            .sib13_v920()
            .mbsfn_area_info_list_r9[i]
            .mcch_cfg_r9.mcch_repeat_period_r9.value;
    sibs13.mbsfn_area_info_list[i].mcch_cfg.mcch_offset =
        cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9[i].mcch_cfg_r9.mcch_offset_r9;
    sibs13.mbsfn_area_info_list[i].mcch_cfg.mcch_mod_period =
        (srsran::mbsfn_area_info_t::mcch_cfg_t::mod_period_t)cfg.sibs[12]
            .sib13_v920()
            .mbsfn_area_info_list_r9[i]
            .mcch_cfg_r9.mcch_mod_period_r9.value;
    sibs13.mbsfn_area_info_list[i].non_mbsfn_region_len = (srsran::mbsfn_area_info_t::region_len_t)cfg.sibs[12]
                                                              .sib13_v920()
                                                              .mbsfn_area_info_list_r9[i]
                                                              .non_mbsfn_region_len.value;
    sibs13.mbsfn_area_info_list[i].notif_ind = cfg.sibs[12].sib13_v920().mbsfn_area_info_list_r9[i].notif_ind_r9;
  }

  // pack MCCH for transmission and pass relevant MCCH values to PHY/MAC
  pack_mcch();
  srsran::mcch_msg_t mcch_t;
  mcch_t.common_sf_alloc_period         = srsran::mcch_msg_t::common_sf_alloc_period_t::rf64;
  mcch_t.nof_common_sf_alloc            = 1;
  srsran::mbsfn_sf_cfg_t sf_alloc_item  = mcch_t.common_sf_alloc[0];
  sf_alloc_item.radioframe_alloc_offset = 0;
  sf_alloc_item.radioframe_alloc_period = srsran::mbsfn_sf_cfg_t::alloc_period_t::n1;
  sf_alloc_item.sf_alloc                = 63;
  mcch_t.nof_pmch_info                  = 1;
  srsran::pmch_info_t* pmch_item        = &mcch_t.pmch_info_list[0];

  pmch_item->nof_mbms_session_info              = 1;
  pmch_item->mbms_session_info_list[0].lc_ch_id = 1;
  if (pmch_item->nof_mbms_session_info > 1) {
    pmch_item->mbms_session_info_list[1].lc_ch_id = 2;
  }
  uint16_t mbms_mcs = cfg.mbms_mcs;
  if (mbms_mcs > 28) {
    mbms_mcs = 28; // TS 36.213, Table 8.6.1-1
    logger.warning("PMCH data MCS too high, setting it to 28");
  }
  logger.debug("PMCH data MCS=%d", mbms_mcs);
  pmch_item->data_mcs         = mbms_mcs;
  pmch_item->mch_sched_period = srsran::pmch_info_t::mch_sched_period_t::rf64;
  pmch_item->sf_alloc_end     = 64 * 6;

  // Configure PHY when PHY is done being initialized
  task_sched.defer_task([this, sibs2, sibs13, mcch_t]() mutable {
    phy->configure_mbsfn(&sibs2, &sibs13, mcch_t);
    mac->write_mcch(&sibs2, &sibs13, &mcch_t, mcch_payload_buffer, current_mcch_length);
    add_user(SRSRAN_MRNTI, {});
  });
}

int rrc::pack_mcch()
{
  mcch.msg.set_c1();
  mbsfn_area_cfg_r9_s& area_cfg_r9      = mcch.msg.c1().mbsfn_area_cfg_r9();
  area_cfg_r9.common_sf_alloc_period_r9 = mbsfn_area_cfg_r9_s::common_sf_alloc_period_r9_e_::rf64;
  area_cfg_r9.common_sf_alloc_r9.resize(1);
  mbsfn_sf_cfg_s* sf_alloc_item          = &area_cfg_r9.common_sf_alloc_r9[0];
  sf_alloc_item->radioframe_alloc_offset = 0;
  sf_alloc_item->radioframe_alloc_period = mbsfn_sf_cfg_s::radioframe_alloc_period_e_::n1;
  sf_alloc_item->sf_alloc.set_one_frame().from_number(32 + 31);

  area_cfg_r9.pmch_info_list_r9.resize(1);
  pmch_info_r9_s* pmch_item = &area_cfg_r9.pmch_info_list_r9[0];
  pmch_item->mbms_session_info_list_r9.resize(1);

  pmch_item->mbms_session_info_list_r9[0].lc_ch_id_r9           = 1;
  pmch_item->mbms_session_info_list_r9[0].session_id_r9_present = true;
  pmch_item->mbms_session_info_list_r9[0].session_id_r9[0]      = 0;
  pmch_item->mbms_session_info_list_r9[0].tmgi_r9.plmn_id_r9.set_explicit_value_r9();
  srsran::plmn_id_t plmn_obj;
  plmn_obj.from_string("00003");
  srsran::to_asn1(&pmch_item->mbms_session_info_list_r9[0].tmgi_r9.plmn_id_r9.explicit_value_r9(), plmn_obj);
  uint8_t byte[] = {0x0, 0x0, 0x0};
  memcpy(&pmch_item->mbms_session_info_list_r9[0].tmgi_r9.service_id_r9[0], &byte[0], 3);

  if (pmch_item->mbms_session_info_list_r9.size() > 1) {
    pmch_item->mbms_session_info_list_r9[1].lc_ch_id_r9           = 2;
    pmch_item->mbms_session_info_list_r9[1].session_id_r9_present = true;
    pmch_item->mbms_session_info_list_r9[1].session_id_r9[0]      = 1;
    pmch_item->mbms_session_info_list_r9[1].tmgi_r9.plmn_id_r9.set_explicit_value_r9() =
        pmch_item->mbms_session_info_list_r9[0].tmgi_r9.plmn_id_r9.explicit_value_r9();
    byte[2] = 1;
    memcpy(&pmch_item->mbms_session_info_list_r9[1].tmgi_r9.service_id_r9[0],
           &byte[0],
           3); // TODO: Check if service is set to 1
  }

  uint16_t mbms_mcs = cfg.mbms_mcs;
  if (mbms_mcs > 28) {
    mbms_mcs = 28; // TS 36.213, Table 8.6.1-1
    logger.warning("PMCH data MCS too high, setting it to 28");
  }

  logger.debug("PMCH data MCS=%d", mbms_mcs);
  pmch_item->pmch_cfg_r9.data_mcs_r9         = mbms_mcs;
  pmch_item->pmch_cfg_r9.mch_sched_period_r9 = pmch_cfg_r9_s::mch_sched_period_r9_e_::rf64;
  pmch_item->pmch_cfg_r9.sf_alloc_end_r9     = 64 * 6;

  const int     rlc_header_len = 1;
  asn1::bit_ref bref(&mcch_payload_buffer[rlc_header_len], sizeof(mcch_payload_buffer) - rlc_header_len);
  if (mcch.pack(bref) != asn1::SRSASN_SUCCESS) {
    logger.error("Failed to pack MCCH message");
  }

  current_mcch_length = bref.distance_bytes(&mcch_payload_buffer[1]);
  current_mcch_length = current_mcch_length + rlc_header_len;
  return current_mcch_length;
}

/*******************************************************************************
  RRC run tti method
*******************************************************************************/

void rrc::tti_clock()
{
  // pop cmds from queue
  rrc_pdu p;
  while (rx_pdu_queue.try_pop(p)) {
    // check if user exists
    auto user_it = users.find(p.rnti);
    if (user_it == users.end()) {
      if (p.pdu != nullptr) {
        log_rx_pdu_fail(p.rnti, p.lcid, *p.pdu, "unknown rnti");
      } else {
        logger.warning("Ignoring rnti=0x%x command %d arg %d. Cause: unknown rnti", p.rnti, p.lcid, p.arg);
      }
      continue;
    }
    ue& ue = *user_it->second;

    // handle queue cmd
    switch (p.lcid) {
      case srb_to_lcid(lte_srb::srb0):
        parse_ul_ccch(ue, std::move(p.pdu));
        break;
      case srb_to_lcid(lte_srb::srb1):
      case srb_to_lcid(lte_srb::srb2):
        parse_ul_dcch(ue, p.lcid, std::move(p.pdu));
        break;
      case LCID_REM_USER:
        rem_user(p.rnti);
        break;
      case LCID_REL_USER:
        process_release_complete(p.rnti);
        break;
      case LCID_ACT_USER:
        user_it->second->set_activity();
        break;
      case LCID_RADLINK_DL:
        user_it->second->set_radiolink_dl_state(p.arg);
        break;
      case LCID_RADLINK_UL:
        user_it->second->set_radiolink_ul_state(p.arg);
        break;
      case LCID_RLC_RTX:
        user_it->second->max_rlc_retx_reached();
        break;
      case LCID_PROT_FAIL:
        user_it->second->protocol_failure();
        break;
      case LCID_EXIT:
        logger.info("Exiting thread");
        break;
      default:
        logger.error("Rx PDU with invalid bearer id: %d", p.lcid);
        break;
    }
  }
}

void rrc::log_rx_pdu_fail(uint16_t rnti, uint32_t lcid, srsran::const_byte_span pdu, const char* cause_str)
{
  logger.error(
      pdu.data(), pdu.size(), "Rx %s PDU, rnti=0x%x - Discarding. Cause: %s", get_rb_name(lcid), rnti, cause_str);
}

void rrc::log_rxtx_pdu_impl(direction_t             dir,
                            uint16_t                rnti,
                            uint32_t                lcid,
                            srsran::const_byte_span pdu,
                            const char*             msg_type)
{
  static const char* dir_str[] = {"Rx", "Tx", "Tx S1AP", "Rx S1AP"};
  fmt::memory_buffer membuf;
  fmt::format_to(membuf, "{} ", dir_str[dir]);
  if (rnti != SRSRAN_PRNTI and rnti != SRSRAN_SIRNTI) {
    if (dir == Tx or dir == Rx) {
      fmt::format_to(membuf, "{} ", srsran::get_srb_name(srsran::lte_lcid_to_srb(lcid)));
    }
    fmt::format_to(membuf, "PDU, rnti=0x{:x} ", rnti);
  } else {
    fmt::format_to(membuf, "Broadcast PDU ");
  }
  fmt::format_to(membuf, "- {} ({} B)", msg_type, pdu.size());

  logger.info(pdu.data(), pdu.size(), "%s", srsran::to_c_str(membuf));
}

void rrc::get_test_msg_from_file(std::string& payload){

  // !inputTestFile.is_open()
  std::string indexFileName = "testFileIndex";

  // Check if the test file is opened
  if (!isTestFileOpen){
    logger.info("Opening a new file");
    srsran::console("Opening a new file\n");

    // Open the idx file to get the details for opening the test file
    std::ifstream indexFile(indexFileName);
    if(!indexFile){
      logger.error("Error: could not open file");
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
            logger.warning("The program was terminated due to the error. Restarting from the line %d", curLineNum);
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
            logger.error("Invalid format in the first line of %s", indexFileName.c_str());
            srsran::console("Invalid format in the first line of %s\n", indexFileName.c_str());
          }
        } else{
          // Reading the testfile for the first time. Usually here.
          logger.info("Opening %s for the first time", testFileName.c_str());
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
                logger.error("Failed to open %s for writing", indexFileName.c_str());
                srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
              }
              indexFile.close();
            } else {
              logger.error("Empty file %s or failed to read the first line.", testFileName.c_str());
              srsran::console("Empty file %s or failed to read the first line.\n", testFileName.c_str());
            }
          } else {
            logger.error("Failed to open %s", testFileName.c_str());
            srsran::console("Failed to open %s\n", testFileName.c_str());
          }

          // Moving the file pointer to the first packet.
          std::getline(inputTestFile, line);
        }
      } else {
        logger.error("Empty file %s or failed to read the first line.", indexFileName.c_str());
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
    logger.info("Reached the end of the file. Opening a new file");
    srsran::console("Reached the end of the file. Opening a new file\n");

    std::string newFileName;
    if (indexFile){
      newFileName = incrementFilename(testFileName);
      indexFile << newFileName << std::endl;
      // log the name of new file
      logger.info("Reading New file %s", newFileName.c_str());
      srsran::console("Reading New file %s\n", newFileName.c_str());

      indexFile.close();
      
      logger.info("Reached the end of the file. Closing the file %s and opening a new file %s", testFileName.c_str(), newFileName.c_str());
      srsran::console("Reached the end of the file. Closing the file %s and opening a new file %s\n", testFileName.c_str(), newFileName.c_str());
    } else {
      logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
    }

    // Close the current file
    inputTestFile.close();
    isTestFileOpen = false;

    // inputTestFile.open(newFileName);

    // Do what we do when we open a new file
    logger.info("Opening %s for the first time", newFileName.c_str());
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
          logger.error("Failed to open %s for writing", indexFileName.c_str());
          srsran::console("Failed to open %s for writing\n", indexFileName.c_str());
        }
        indexFile.close();
      } else {
        logger.error("Empty file %s or failed to read the first line.", newFileName.c_str());
        srsran::console("Empty file %s or failed to read the first line.\n", newFileName.c_str());
      }
    } else {
      logger.error("Failed to open %s", newFileName.c_str());
      srsran::console("Failed to open %s\n", newFileName.c_str());
    }
    // Skipping the first line
    std::getline(inputTestFile, line);
  }

  // getline and update the first line
  std::getline(inputTestFile, line);
  logger.info("Get line from %s", testFileName.c_str());
  srsran::console("Get line from %s\n", testFileName.c_str());

  // Update the current line number
  curLineNum++;

  // Update the index file
  std::ofstream indexFile(indexFileName);
  if (indexFile){
    indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
    indexFile.close();
  } else {
    logger.error("Failed to open %s for writing", indexFileName.c_str());
    srsran::console("Failed to open %s for writing", indexFileName.c_str());
  }

  // Split the line into components using ',' as the delimiter and pass it to the payload
  srsran::console("Debug: line is %s\n", line.c_str());

  std::istringstream lineStream(line);
  std::string numbering, filepayload, msgName, fieldName;
  std::getline(lineStream, numbering, ',');
  std::getline(lineStream, filepayload, ',');
  std::getline(lineStream, msgName, ',');
  std::getline(lineStream, fieldName);

  if (cfg.temp_blacklist){
    // Temporally blacklist msg+fields, when it fired oracle for {threshold} times. 

    std::string key = msgName+","+fieldName;
    bool blacklistThisMessage = false;
  
    // Check if the msgName and field Name is in the blacklist
    for (const std::string& msgField : blacklistMsgField){
      if (msgField == key){
        blacklistThisMessage = true;
        srsran::console("Blacklisting target detected\n");
        temp_blacklist_test_cases(key);
      }
    }

    if (blacklistThisMessage){
      
      do {
        // getline and update the first line
        if (!std::getline(inputTestFile, line)) {
          srsran::console("No more lines to read!");
          break;
        }
      
        curLineNum++;
        logger.info("Get line from %s", testFileName.c_str());
        srsran::console("Get line from %s\n", testFileName.c_str());

        std::istringstream lineStream2(line);

        std::getline(lineStream2, numbering, ',');
        std::getline(lineStream2, filepayload, ',');
        std::getline(lineStream2, msgName, ',');
        std::getline(lineStream2, fieldName);

        payload = filepayload;
        
        key = msgName+","+fieldName;
        blacklistThisMessage = false;

        for (const std::string& msgField : blacklistMsgField){
          if (msgField == key){
            blacklistThisMessage = true;
            srsran::console("Blacklisting target detected\n");
            temp_blacklist_test_cases(key);
          }
        }
      } while (blacklistThisMessage);
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
    // Update the index file
    std::ofstream indexFile(indexFileName);
    if (indexFile){
      indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
      indexFile.close();
    } else {
      logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing", indexFileName.c_str());
    }

    // Split the line into components using ',' as the delimiter and pass it to the payload
    srsran::console("Debug: line is %s\n", line.c_str());

  }

  if (cfg.replay_mode){
    // During replay, support skipping certain msg+field combinations

    bool skipThisMessage = false;
    // std::vector<std::string> skipMsgFields = {"dlInformationTransfer, dedicatedInfoNAS"};
    // std::vector<std::string> skipMsgFields = {"dlInformationTransfer,message"};
    std::vector<std::string> skipMsgFields = {};

    for (const std::string& skipMsgField : skipMsgFields){
      if (skipMsgField == msgName+","+fieldName){
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
        logger.info("Get line from %s", testFileName.c_str());
        srsran::console("Get line from %s\n", testFileName.c_str());

        std::istringstream lineStream2(line);

        std::getline(lineStream2, numbering, ',');
        std::getline(lineStream2, filepayload, ',');
        std::getline(lineStream2, msgName, ',');
        std::getline(lineStream2, fieldName);

        payload = filepayload;
        


        skipThisMessage = false;

        for (const std::string& skipMsgField : skipMsgFields){
          if (skipMsgField == msgName+","+fieldName){
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
    // Update the index file
    std::ofstream indexFile(indexFileName);
    if (indexFile){
      indexFile << testFileName << "," << curLineNum << "," << totalLineNum << std::endl;
      indexFile.close();
    } else {
      logger.error("Failed to open %s for writing", indexFileName.c_str());
      srsran::console("Failed to open %s for writing", indexFileName.c_str());
    }

    // Split the line into components using ',' as the delimiter and pass it to the payload
    srsran::console("Debug: line is %s\n", line.c_str());

  }
    
  
  payload = filepayload;

  // Put the message to the candidates queue
  put_test_message_queue(payload+","+msgName+","+fieldName);
  log_timestamp(numbering);

}

std::string rrc::incrementFilename(const std::string& filename){
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

void rrc::put_test_message_queue(const std::string& test_message){
  test_message_queue.push(test_message);

  while (test_message_queue.size() > maxSize) {
    test_message_queue.pop();
  }

}

std::vector<std::string> rrc::get_recent_messages(){
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

void rrc::save_recent_messages(const std::string& directoryPath, const std::string& candidate, int order){

  // Check if directoryPath exists. 
  struct stat st;
  if (stat(directoryPath.c_str(), &st) != 0){
    // Directory doesn't exist, so create it
    if (mkdir(directoryPath.c_str(), 0775) == 0){
      logger.info("Created directory %s", directoryPath.c_str());
    } else {
      logger.error("1Failed to create directory %s", directoryPath.c_str());
      srsran::console("1Failed to create directory %s\n", directoryPath.c_str());
      perror("mkdir");
    }

    // Also create a directory for crashes which is inside the directoryPath
    std::string crashesDirectory = directoryPath + "/crashes";
    if (mkdir(crashesDirectory.c_str(), 0775) == 0){
      logger.info("Created directory %s", crashesDirectory.c_str());
    } else {
      logger.error("2Failed to create directory %s", crashesDirectory.c_str());
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
        if (std::getline(inputStream, pathes)) {
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
          logger.error("Failed to get pathes from the input string");
          srsran::console("Failed to get pathes from the input string\n");
        }
      } else {
        logger.error("Failed to get msgName from the input string");
        srsran::console("Failed to get msgName from the input string\n");
      }
    } else {
      logger.error("Failed to get payload from the input string");
      srsran::console("Failed to get payload from the input string\n");
    }

    //TODO: put the path info
    //TODO2: put the best candidate
    // jsonData[std::to_string(payloadCounter)] = {
    //   {"Payload", payload},
    //   {"crashCounter", crashCounter}
    // };

    payloadCounter++;
  }

  if ((!candidate.empty())){
    // Split the input string into payload and path elements
    std::istringstream inputStream(candidate);
    std::string can_payload, can_msgName, can_pathes;

    // Parse the Best candidate string
    if (std::getline(inputStream, can_payload, ',')){
      if (std::getline(inputStream, can_msgName, ',')) {
        if (std::getline(inputStream, can_pathes)) {
        } else {
          logger.error("Failed to get pathes from the input string");
          srsran::console("Failed to get pathes from the input string\n");
        }
      } else {
        logger.error("Failed to get msgName from the input string");
        srsran::console("Failed to get msgName from the input string\n");
      }
    } else {
      logger.error("Failed to get payload from the input string");
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
  // if (!std::experimental::filesystem::exists(crashDirectory)){
  //   std::experimental::filesystem::create_directory(crashDirectory);
  // }

  // Check if directory exists, and create it if it doesn't
  // struct stat st;
  if (stat(crashDirectory.c_str(), &st) != 0){
    // Directory doesn't exist, so create it
    if (mkdir(crashDirectory.c_str(), 0775) == 0){
      logger.info("Created directory %s", crashDirectory.c_str());
    } else {
      logger.error("1Failed to create directory %s", crashDirectory.c_str());
      srsran::console("1Failed to create directory %s\n", crashDirectory.c_str());
      perror("mkdir");
    }
  } else {
    // Crash directory exists, so create a new directory with a new crash number
    crashDirectory = GetNextCrashDirectory(directoryPath);

    // // Make a directory with a latest crash number
    // if (mkdir(crashDirectory.c_str(), 0775) == 0){
    //   logger.info("Created directory %s", crashDirectory.c_str());
    // } else {
    //   logger.error("3Failed to create directory %s", crashDirectory.c_str());
    //   srsran::console("3Failed to create directory %s\n", crashDirectory.c_str());
    //   perror("mkdir");
    // }
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

  

  // Save the json object to a file
  std::string filename = crashDirectory + "/candidates.json";
  std::ofstream file(filename);
  file << jsonData.dump(4);
  file.close();
}


// This is called when a directory alread exists during saving. 
std::string rrc::GetNextCrashDirectory(const std::string& directoryPath){
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
    logger.error("Failed to open %s", countFilePath.c_str());
    srsran::console("Failed to open %s\n", countFilePath.c_str());
  }

  // Increament the count
  nextCrashNumber++;

  std::stringstream nextCrashDirStream;
  nextCrashDirStream << directoryPath << "/crashes/crash_" << nextCrashNumber;
  std::string nextCrashDirectory = nextCrashDirStream.str();

  // Create the next crash directory
  if (mkdir(nextCrashDirectory.c_str(), 0775) == 0){
    logger.info("Created directory %s", nextCrashDirectory.c_str());
    // Update the count in the file
    std::ofstream updatedCountFile(countFilePath);
    updatedCountFile.close();

    // Also update the crashCounter
    crashCounter = nextCrashNumber;
  } else {
    logger.error("Failed to create directory %s", nextCrashDirectory.c_str());
    srsran::console("Failed to create directory %s\n", nextCrashDirectory.c_str());
  }

  return nextCrashDirectory;

}

// This is used within the same test file, during the consecutive testing (mutation for same fields)
void rrc::blacklist_test_cases(std::string& blacklist_msgName_path){
  // Split the input string into payload, msgName and path elements
  std::istringstream inputStream(blacklist_msgName_path);
  std::string payload, blacklist_msgName_and_paths;

  // Parse the Best candidate string
  if (std::getline(inputStream, payload, ',')){
    if (std::getline(inputStream, blacklist_msgName_and_paths)) {
    } else {
      logger.error("Failed to get msgName and pathes from the input string");
      srsran::console("Failed to get msgName and pathes from the input string\n");
    }
  } else {
    logger.error("Failed to get payload from the input string");
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
    logger.info("Debug: msgName_and_paths is %s\n and target blacklist is %s", msgName_and_paths.c_str(), blacklist_msgName_and_paths.c_str());
  } while (blacklist_msgName_and_paths == msgName_and_paths);

  srsran::console("Done with the while loop, curLineNum is %d", curLineNum);
  curLineNum--;
  inputTestFile.seekg(curPos);

}

// Temporary black list msg+field for N messages. 
void rrc::temp_blacklist_test_cases(std::string& blacklist_msgName_path){
  // Split the input string into payload, msgName and path elements
  std::istringstream inputStream(blacklist_msgName_path);
  std::string payload, blacklist_msgName_and_paths;

  // Parse the input string
  if (std::getline(inputStream, payload, ',')){
    if (std::getline(inputStream, blacklist_msgName_and_paths)) {
    } else {
      logger.error("Failed to get msgName and pathes from the input string");
      srsran::console("Failed to get msgName and pathes from the input string\n");
    }
  } else {
    logger.error("Failed to get payload from the input string");
    srsran::console("Failed to get payload from the input string\n");
  }
  
  // Increase the counter
  blacklistMsgFieldCount[blacklist_msgName_and_paths]++;
  logger.info("blacklistMsgFieldCount[%s] is %d", blacklist_msgName_and_paths.c_str(), blacklistMsgFieldCount[blacklist_msgName_and_paths]);

  // Check if the counter reached the max count
  if (blacklistMsgFieldCount[blacklist_msgName_and_paths] == maxCount) {
    srsran::console("Reached the max count for %s\n", blacklist_msgName_and_paths.c_str());
    logger.info("Reached the max count for %s", blacklist_msgName_and_paths.c_str());

    // Add the msgName and pathes to the blacklist
    if (find(blacklistMsgField.begin(), blacklistMsgField.end(), blacklist_msgName_and_paths) == blacklistMsgField.end()) {
      blacklistMsgField.push_back(blacklist_msgName_and_paths);
    }
  }

  // Reset the counters after the counter reaches the threashold value. 
  if (blacklistMsgFieldCount[blacklist_msgName_and_paths] >= resetThreshold){
    blacklistMsgFieldCount[blacklist_msgName_and_paths] = 0;

    // Also, remove the target from the blacklist
    blacklistMsgField.erase(std::remove(blacklistMsgField.begin(), blacklistMsgField.end(), blacklist_msgName_and_paths), blacklistMsgField.end());
  }

}

// rrc class function called toggle_airplane_mode that takes a string name of the device as an argument
// and toggles the airplane mode on the device.
// Device-specific 
void rrc::toggle_airplane_mode(const std::string& device_name){

  // Check if the device name is valid
  airplanemode_attempt++;

  // Galaxy S8
  const char* commands_s8[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 950 370 &"
  };

  const char* command_S8_single[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell input tap 950 370 &"
  };

  // Galaxy ZFlip4
  const char* commands_Z4[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 530 2320 &"
    "adb shell input tap 945 420 &"
  };

  const char* command_Z4_single[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell input tap 530 2320 &"
    "adb shell input tap 945 420 &"
  };
  
  // Galaxy S20
  const char* commands_s20[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 550 2100 &",
    "adb shell input tap 950 370 &"
  };

  // Galaxy Note8
  const char* commands_note8[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    // "adb shell input tap 540 1950 &",
    "adb shell input tap 950 370 &"
  };

  // Galaxy A32
  const char* command_A32[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 540 2150 &",
    "adb shell input tap 950 370 &"
  };

  const char* commands_s21[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 530 2100 &",
    "adb shell input tap 945 400 &"
  };

  const char* command_s21_single[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell input tap 945 400 &"
  };

  const char* commands_p20[] = {
    "adb shell input keyevent KEYCODE_WAKEUP &",
    "adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS &",
    "adb shell input tap 960 360 &",
  };

  std::vector<std::future<int>> futures;

  uint time_interval = 0; // 100ms
  if (device_name == "S8" || device_name == "Galaxy_S8" || device_name == "S10"|| device_name == "Galaxy_S10" || device_name == "A31" || device_name == "S20"){
    /*
    // Turn off the airplane mode
    logger.info("Turning off the airplane mode");
    srsran::console("Turning off the airplane mode\n");

    // Optional: Swipe the screen if needed
    // system("adb shell input swipe 350 1800 350 300");

    // Wake up the device
    if (system("adb shell input keyevent KEYCODE_WAKEUP") != 0){
      logger.error("Failed to wake up the device");
      srsran::console("Failed to wake up the device\n");
    }
    usleep(time_interval); // 100ms 

    // Go to the airplane mode settings
    if (system("adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS") != 0){
      logger.error("Failed to go to the airplane mode settings");
      srsran::console("Failed to go to the airplane mode settings\n");
    }
    usleep(time_interval); // 100ms

    // // Click the airplane mode button
    // if (system("adb shell input keyevent KEYCODE_DPAD_RIGHT") != 0){
    //   logger.error("Failed to click the airplane mode button");
    //   srsran::console("Failed to click the airplane mode button\n");
    // }
    // usleep(time_interval); // 100ms

    // if (system("adb shell input keyevent KEYCODE_DPAD_RIGHT") != 0){
    //   logger.error("Failed to click the airplane mode button");
    //   srsran::console("Failed to click the airplane mode button\n");
    // }
    // usleep(time_interval); // 100ms

    // if (system("adb shell input keyevent KEYCODE_DPAD_CENTER") != 0){
    //   logger.error("Failed to click the airplane mode button");
    //   srsran::console("Failed to click the airplane mode button\n");
    // }
    // usleep(time_interval); // 100ms

    if (system("adb shell input tap 950 370") != 0){
      logger.error("Failed to click the airplane mode button");
      srsran::console("Failed to click the airplane mode button\n");
    }
    */
    for (const char* command : commands_s8){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
      // usleep(time_interval); // 100ms
      // futures.back().wait();
    }

    
  } else if (device_name == "S8_single" || device_name == "A32_single"){
    for (const char* command : command_S8_single){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "Z4" || device_name == "Galaxy_ZFlip4"){
    for (const char* command : commands_Z4){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "Z4_single"){
    for (const char* command : command_Z4_single){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "S21" || device_name == "Galaxy_S21"){
    for (const char* command : commands_s21){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "S21_single"){
    for (const char* command : command_s21_single){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "A32"){
    for (const char* command : command_A32){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "S20" || device_name == "Galaxy_S20"){
    for (const char* command : commands_s20){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "Note8"){
    for (const char* command : commands_note8){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else if (device_name == "P20"){
    for (const char* command : commands_p20){
      futures.push_back(std::async(std::launch::async, executeShellCommand, command));
    }
  } else {
    logger.error("Invalid device name");
    srsran::console("Invalid device name\n");
  }
}

int rrc::executeShellCommand(const char* command){
  int result = std::system(command);
  usleep(delay_command); // 900ms
  if (result !=0 ){
    // error
    // logger.error("Failed to execute the command %s", command);
  }
  return result;
}

void rrc::log_timestamp(std::string& msgNum){
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
    logger.error("Failed to open the log file");
    srsran::console("Failed to open the log file\n");
  }
  
}

  

} // namespace srsenb
