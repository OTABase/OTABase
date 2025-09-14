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
#ifndef SRSEPC_S1AP_H
#define SRSEPC_S1AP_H

#include "mme_gtpc.h"
#include "nas.h"
#include "s1ap_ctx_mngmt_proc.h"
#include "s1ap_erab_mngmt_proc.h"
#include "s1ap_mngmt_proc.h"
#include "s1ap_nas_transport.h"
#include "s1ap_paging.h"
#include "srsepc/hdr/hss/hss.h"
#include "srsran/asn1/gtpc.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/s1ap.h"
#include "srsran/common/common.h"
#include "srsran/common/s1ap_pcap.h"
#include "srsran/common/standard_streams.h"
#include "srsran/interfaces/epc_interfaces.h"
#include "srsran/srslog/srslog.h"
#include <arpa/inet.h>
#include <map>
#include <netinet/sctp.h>
#include <set>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <queue>
#include "srsran/common/json.hpp"
#include <sstream>
#include <cstdlib>
#include <future>
#include <chrono>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>
#include "srsran/common/task_scheduler.h"


using json = nlohmann::json;


namespace srsepc {

const uint16_t S1MME_PORT = 36412;

using s1ap_pdu_t = asn1::s1ap::s1ap_pdu_c;

class s1ap : public s1ap_interface_nas, public s1ap_interface_gtpc, public s1ap_interface_mme
{
public:
  static s1ap* get_instance();
  static void  cleanup();

  int  enb_listen();
  int  init(const s1ap_args_t& s1ap_args);
  void stop();

  int get_s1_mme();

  void delete_enb_ctx(int32_t assoc_id);

  bool s1ap_tx_pdu(const s1ap_pdu_t& pdu, struct sctp_sndrcvinfo* enb_sri);
  void handle_s1ap_rx_pdu(srsran::byte_buffer_t* pdu, struct sctp_sndrcvinfo* enb_sri);
  void handle_initiating_message(const asn1::s1ap::init_msg_s& msg, struct sctp_sndrcvinfo* enb_sri);
  void handle_successful_outcome(const asn1::s1ap::successful_outcome_s& msg);

  void activate_eps_bearer(uint64_t imsi, uint8_t ebi);

  void print_enb_ctx_info(const std::string& prefix, const enb_ctx_t& enb_ctx);

  uint32_t   get_plmn();
  uint16_t   get_tac();
  uint32_t   get_next_mme_ue_s1ap_id();
  enb_ctx_t* find_enb_ctx(uint16_t enb_id);
  void       add_new_enb_ctx(const enb_ctx_t& enb_ctx, const struct sctp_sndrcvinfo* enb_sri);
  void       get_enb_ctx(uint16_t sctp_stream);

  bool add_nas_ctx_to_imsi_map(nas* nas_ctx);
  bool add_nas_ctx_to_mme_ue_s1ap_id_map(nas* nas_ctx);
  bool add_ue_to_enb_set(int32_t enb_assoc, uint32_t mme_ue_s1ap_id);

  virtual nas* find_nas_ctx_from_imsi(uint64_t imsi);
  nas*         find_nas_ctx_from_mme_ue_s1ap_id(uint32_t mme_ue_s1ap_id);

  bool         release_ue_ecm_ctx(uint32_t mme_ue_s1ap_id);
  void         release_ues_ecm_ctx_in_enb(int32_t enb_assoc);
  virtual bool delete_ue_ctx(uint64_t imsi);

  uint32_t         allocate_m_tmsi(uint64_t imsi);
  virtual uint64_t find_imsi_from_m_tmsi(uint32_t m_tmsi);

  s1ap_args_t           m_s1ap_args;
  srslog::basic_logger& m_logger = srslog::fetch_basic_logger("S1AP");

  s1ap_mngmt_proc*      m_s1ap_mngmt_proc;
  s1ap_nas_transport*   m_s1ap_nas_transport;
  s1ap_ctx_mngmt_proc*  m_s1ap_ctx_mngmt_proc;
  s1ap_erab_mngmt_proc* m_s1ap_erab_mngmt_proc;
  s1ap_paging*          m_s1ap_paging;

  std::map<uint32_t, uint64_t>   m_tmsi_to_imsi;
  std::map<uint16_t, enb_ctx_t*> m_active_enbs;

  // Interfaces
  virtual bool send_initial_context_setup_request(uint64_t imsi, uint16_t erab_to_setup);
  virtual bool send_ue_context_release_command(uint32_t mme_ue_s1ap_id);
  virtual bool send_erab_release_command(uint32_t               enb_ue_s1ap_id,
                                         uint32_t               mme_ue_s1ap_id,
                                         std::vector<uint16_t>  erabs_to_release,
                                         struct sctp_sndrcvinfo enb_sri);
  virtual bool send_erab_modify_request(uint32_t                     enb_ue_s1ap_id,
                                        uint32_t                     mme_ue_s1ap_id,
                                        std::map<uint16_t, uint16_t> erabs_to_be_modified,
                                        srsran::byte_buffer_t*       nas_msg,
                                        struct sctp_sndrcvinfo       enb_sri);
  virtual bool send_downlink_nas_transport(uint32_t               enb_ue_s1ap_id,
                                           uint32_t               mme_ue_s1ap_id,
                                           srsran::byte_buffer_t* nas_msg,
                                           struct sctp_sndrcvinfo enb_sri);
  virtual bool send_paging(uint64_t imsi, uint16_t erab_to_setup);
  virtual bool send_nas_test_message_from_py(nas* nas_ctx);
  virtual bool send_paging_message(nas* nas_ctx);
  virtual bool send_error_indication(nas* nas_ctx, uint16_t cause);
  virtual bool handle_nas_oracle(nas* nas_ctx);

  virtual bool expire_nas_timer(enum nas_timer_type type, uint64_t imsi);

  // virtual bool         get_is_backtracking();
  // virtual void         set_is_backtracking(bool mode);
  // virtual uint64_t     get_backtracking_num();
  // virtual void         set_backtracking_num(uint64_t btrk_num);
  // virtual std::string  get_backtracking_msg();
  // virtual std::string  get_logging_path();
  virtual void         save_recent_messages(const std::string& directoryPath, const std::string& candidate = "", int order = 0);
  // const std::string& directoryPath, const std::string& candidate = "", int order = 0
 
  int total_sent_msg = 0;
  int total_sent_msg_inc_oracle = 0;
  // Oracle related features
  uint16_t check_period;
  bool     is_waiting_for_id_req;
  uint16_t oracle_cnt = 0;
  void send_nas_id_req(nas* nas_ctx);
 
  // Features related to the backtracking
  bool          is_backtracking = false;
  uint64_t      backtracking_num = 0;
  uint64_t      backtracking_num_total = 0;
  std::string   backtracking_msg = "";
  
  // Used for read/write test file
  std::ifstream  inputTestFile;
  std::string    testFileName;
  bool           isTestFileOpen = false;
  bool           isTestFileEnd  = false;
  int            totalLineNum   = 0;
  int            curLineNum     = 1;
  std::streampos firstPos;
  std::streampos curPos;
  void           get_test_msg_from_file(std::string& payload);
  std::string    incrementFilename(const std::string& filename);
 
  // Used for managing the candidate test cases.
  std::queue<std::string> test_message_queue;
  size_t                  maxSize;
  int                     crashCounter;
 
  // Used for logging the candidates
  void                     put_test_message_queue(const std::string& test_message);
  std::vector<std::string> get_recent_messages();
  // void                     save_recent_messages(const std::string& directoryPath, const std::string& candidate = "", int order = 0);
  std::string              GetNextCrashDirectory(const std::string& directoryPath);
  std::string              logging_path;
  
  // Used for blacklisting
  void blacklist_test_cases(std::string& blacklist_msgName_path);
 
  // Used for timestamp logging
  // std::ofstream logfile("data.csv");
  std::ofstream logfile;
  std::string logfile_name;
  void log_timestamp(std::string& msgNum); 

  bool send_nas_test_message_backtracking(nas* nas_ctx);

private:
  s1ap();
  virtual ~s1ap();

  static s1ap* m_instance;

  uint32_t m_plmn;

  hss_interface_nas*                     m_hss;
  int                                    m_s1mme;
  std::map<int32_t, uint16_t>            m_sctp_to_enb_id;
  std::map<int32_t, std::set<uint32_t> > m_enb_assoc_to_ue_ids;

  std::map<uint64_t, nas*> m_imsi_to_nas_ctx;
  std::map<uint32_t, nas*> m_mme_ue_s1ap_id_to_nas_ctx;

  uint32_t m_next_mme_ue_s1ap_id;
  uint32_t m_next_m_tmsi;

  // GTP-C Interface
  mme_gtpc* m_mme_gtpc;

  // PCAP
  bool              m_pcap_enable;
  srsran::s1ap_pcap m_pcap;
};

inline uint32_t s1ap::get_plmn()
{
  return m_plmn;
}

inline uint16_t s1ap::get_tac()
{
  return m_s1ap_args.tac;
}

} // namespace srsepc
#endif // SRSEPC_S1AP_H
