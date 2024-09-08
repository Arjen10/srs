//
// Created by Arjen on 2024/9/7.
//

#ifndef SRS_SRS_APP_GB28181_UDP_HPP
#define SRS_SRS_APP_GB28181_UDP_HPP


#include <srs_app_listener.hpp>
#include <srs_app_config.hpp>
#include <srs_core.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_protocol_conn.hpp>
#include <srs_protocol_http_conn.hpp>
#include <srs_app_gb28181.hpp>

using namespace std;

class SrsGbSipUdpReadWriter;
class SrsGbSipUDPSender;

class SrsGbUDPListener : public ISrsListener, public ISrsUdpMuxHandler
{
private:
    SrsConfDirective* conf_;
    SrsUdpMuxListener* sip_udp_listener_;
public:
    SrsGbUDPListener();
    virtual ~SrsGbUDPListener();
public:
    srs_error_t initialize(SrsConfDirective* conf);
    srs_error_t listen();
    void close();
    srs_error_t on_udp_packet(SrsUdpMuxSocket *skt);
};

class SrsGbUDPSession : public ISrsResource, public ISrsCoroutineHandler, public ISrsExecutorHandler {
private:
    SrsContextId cid_;
    SrsGbSipUDPSender* sender_;
private:
    SrsGbSessionState state_;
    SrsSipMessage* register_;
private:
    // The candidate for SDP in configuration.
    std::string candidate_;
    // The public IP for SDP, generated by SRS.
    std::string pip_;
    // When wait for SIP and media connecting, timeout if exceed.
    srs_utime_t connecting_starttime_;
    // The max timeout for connecting.
    srs_utime_t connecting_timeout_;
    // The time we enter reinviting state.
    srs_utime_t reinviting_starttime_;
    // The wait time for re-invite.
    srs_utime_t reinvite_wait_;
    // The number of timeout, dispose session if exceed.
    uint32_t nn_timeout_;
public:
    SrsGbUDPSession(SrsUdpMuxSocket* skt);
    virtual ~SrsGbUDPSession();
public:
// Interface ISrsExecutorHandler
public:
    virtual void on_executor_done(ISrsInterruptable* executor);
public:
    // When got a pack of messages.
    void on_ps_pack(SrsPackContext* ctx, SrsPsPacket* ps, const std::vector<SrsTsMessage*>& msgs);
    void drive_state(SrsSipMessage* msg);
    srs_error_t on_sip_message(SrsSipMessage* msg);
    // When got available SIP transport.
    void on_sip_transport(SrsUdpMuxSocket* skt);
    void register_response(SrsSipMessage* msg);
    // Enqueue a SIP message to send, which might be a request or response.
    void enqueue_sip_message(SrsSipMessage* msg);
// Interface ISrsCoroutineHandler
public:
    virtual srs_error_t cycle();
// Interface ISrsResource
public:
    virtual const SrsContextId& get_id();
    virtual std::string desc();
};

class SrsGbSipUDPSender : public ISrsStartable, public ISrsCoroutineHandler
{
private:
    SrsCoroutine* trd_;
    SrsUdpMuxSocket* skt_;
private:
    std::vector<SrsSipMessage*> msgs_;
    srs_cond_t wait_;
public:
    SrsGbSipUDPSender(SrsUdpMuxSocket* skt);
    virtual ~SrsGbSipUDPSender();
public:
    // Push message to queue, and sender will send out in dedicate coroutine.
    void enqueue(SrsSipMessage* msg);
    // Interrupt the sender coroutine.
    void interrupt();
    // Set the cid of all coroutines.
    virtual void set_cid(const SrsContextId& cid);
// Interface ISrsStartable
public:
    virtual srs_error_t start();
// Interface ISrsCoroutineHandler
public:
    virtual srs_error_t cycle();
private:
    srs_error_t do_cycle();
};

class SrsGbSipUdpReadWriter: public ISrsProtocolReadWriter
{
private:
    SrsUdpMuxSocket* skt_;
    SrsUdpMuxSocket* skt_sendonly_;
public:
    SrsGbSipUdpReadWriter(SrsUdpMuxSocket* skt);

    ~SrsGbSipUdpReadWriter();
public:
    virtual void set_recv_timeout(srs_utime_t tm);
    virtual srs_utime_t get_recv_timeout();
    virtual srs_error_t read(void* buf, size_t size, ssize_t* nread);
    virtual srs_error_t read_fully(void* buf, size_t size, ssize_t* nread);
    virtual int64_t get_recv_bytes();
    virtual int64_t get_send_bytes();
    virtual void set_send_timeout(srs_utime_t tm);
    virtual srs_utime_t get_send_timeout();
    virtual srs_error_t write(void* buf, size_t size, ssize_t* nwrite);
    virtual srs_error_t writev(const iovec *iov, int iov_size, ssize_t* nwrite);
};

#endif //SRS_SRS_APP_GB28181_UDP_HPP
