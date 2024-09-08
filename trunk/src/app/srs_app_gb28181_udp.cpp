//
// Created by Arjen on 2024/9/7.
//

#include <srs_app_gb28181_udp.hpp>

SrsGbUDPListener::SrsGbUDPListener() {
    conf_ = NULL;
}

SrsGbUDPListener::~SrsGbUDPListener() {
    srs_freep(conf_);
    srs_freep(sip_udp_listener_);
}

srs_error_t SrsGbUDPListener::initialize(SrsConfDirective *conf) {
    srs_error_t err = srs_success;

    srs_freep(conf_);
    conf_ = conf->copy();

    string ip = srs_any_address_for_listener();

    bool sip_enabled = _srs_config->get_stream_caster_sip_enable(conf);
    if (!sip_enabled) {
        return srs_error_new(ERROR_GB_CONFIG, "GB SIP is required");
    }
    int port = _srs_config->get_stream_caster_sip_listen(conf);
    sip_udp_listener_ = new SrsUdpMuxListener(this, ip, port);

    return err;
}

void SrsGbUDPListener::close() {

}

srs_error_t SrsGbUDPListener::listen() {
    srs_error_t err = srs_success;
    if ((err = sip_udp_listener_->listen()) != srs_success) {
        return srs_error_wrap(err, "listen");
    }
    int port = _srs_config->get_stream_caster_sip_listen(conf_);
    srs_trace("SIP-UDP listen at upp://:%d, fd=%d", port, sip_udp_listener_->fd());
    return err;
}

srs_error_t SrsGbUDPListener::on_udp_packet(SrsUdpMuxSocket *skt) {
    srs_error_t err = srs_success;
    SrsHttpParser parser;

    // We might get SIP request or response message.
    if ((err = parser.initialize(HTTP_BOTH)) != srs_success) {
        return srs_error_wrap(err, "init parser");
    }

    // Use HTTP parser to parse SIP messages.
    ISrsHttpMessage* hmsg = NULL;
    SrsGbSipUdpReadWriter reader(skt);
    if ((err = parser.parse_message(&reader, &hmsg)) != srs_success) {
        return srs_error_wrap(err, "parse message");
    }

    SrsSipMessage smsg;
    if ((err = smsg.parse(hmsg)) != srs_success) {
        srs_warn("SIP: Drop msg type=%d, method=%d, err is %s", hmsg->message_type(), hmsg->method(), srs_error_summary(err).c_str());
        srs_freep(err);
    }
    // Find exists session for register, might be created by another object and still alive.
    string device_id = smsg.device_id();
    SrsSharedResource<SrsGbUDPSession>* session = dynamic_cast<SrsSharedResource<SrsGbUDPSession>*>(_srs_gb_manager->find_by_id(device_id));
    SrsGbUDPSession* raw_session = session ? (*session).get() : NULL;
    if (!raw_session) {
        raw_session = new SrsGbUDPSession(skt);
        session = new SrsSharedResource<SrsGbUDPSession>(raw_session);
        _srs_gb_manager->add_with_id(device_id, session);
        // 启动协程
        SrsExecutorCoroutine* executor = new SrsExecutorCoroutine(_srs_gb_manager, raw_session, raw_session, raw_session);
        if ((err = executor->start()) != srs_success) {
            srs_freep(executor);
            return srs_error_wrap(err, "session");
        }
    }
    raw_session->on_sip_transport(skt);
    srs_trace("UDP-SIP: msg type=%d, contact_host %s, contact_host %d",  smsg.type_, smsg.via_send_by_address_.c_str(), smsg.via_send_by_port_);
    srs_trace("UDP-SIP: device_id=%d raw_session's address=%d", device_id.c_str(), raw_session);
    raw_session->on_sip_message(&smsg);
    return err;
}

SrsGbUDPSession::SrsGbUDPSession(SrsUdpMuxSocket* skt)
{
    cid_ = _srs_context->generate_id();
    sender_ = new SrsGbSipUDPSender(skt);
    state_ = SrsGbSessionStateInit;
    register_ = new SrsSipMessage();
    connecting_starttime_ = 0;
    connecting_timeout_ = 0;
    reinviting_starttime_ = 0;
    reinvite_wait_ = 0;
    nn_timeout_ = 0;
}

SrsGbUDPSession::~SrsGbUDPSession() {
    srs_freep(register_);
    srs_freep(sender_);
}

void SrsGbUDPSession::drive_state(SrsSipMessage* msg)
{

}

srs_error_t SrsGbUDPSession::on_sip_message(SrsSipMessage* msg)
{
    srs_error_t err = srs_success;
    // For state to use device id from register message.
    if (msg->is_register()) {
        srs_freep(register_);
        // Cache the register request message.
        register_ = msg->copy();
    }

    drive_state(msg);

    // Notify session about the SIP message.
    if (msg->is_register()) {
        // Response for REGISTER.
        register_response(msg);
        return err;
    }

    if (msg->is_message()) {
        return err;
    }

    if (msg->is_invite_ok()) {
        return err;
    }

    if (msg->is_bye()) {
        return err;
    }

    if (msg->is_trying() || msg->is_bye_ok()) {
        // Ignore SIP message 100(Trying).
        // Ignore BYE ok.
        return err;
    }

    srs_warn("SIP: Ignore message type=%d, status=%d, method=%d, body=%s", msg->type_,
             msg->status_, msg->method_, msg->body_escaped_.c_str());

    return err;
}

void SrsGbUDPSession::on_sip_transport(SrsUdpMuxSocket* skt)
{
}

void SrsGbUDPSession::register_response(SrsSipMessage* msg)
{
    SrsSipMessage* res = new SrsSipMessage();

    res->type_ = HTTP_RESPONSE;
    res->status_ = HTTP_STATUS_OK;
    res->via_ = msg->via_;
    res->from_ = msg->from_;
    res->to_ = msg->to_;
    res->cseq_ = msg->cseq_;
    res->call_id_ = msg->call_id_;
    res->contact_ = msg->contact_;
    res->expires_ = msg->expires_;
    enqueue_sip_message(res);
}

void SrsGbUDPSession::enqueue_sip_message(SrsSipMessage* msg)
{
    sender_->enqueue(msg);
}

srs_error_t SrsGbUDPSession::cycle()
{
    srs_error_t err = srs_success;
    if ((err = sender_->start()) != srs_success) {
        return srs_error_wrap(err, "spi udp sender");
    }
    return err;
}

void SrsGbUDPSession::on_executor_done(ISrsInterruptable* executor)
{

}

const SrsContextId& SrsGbUDPSession::get_id()
{
    return cid_;
}

std::string SrsGbUDPSession::desc()
{
    return "GBS";
}

SrsGbSipUDPSender::SrsGbSipUDPSender(SrsUdpMuxSocket* skt)
{
    skt_ = skt;
    wait_ = srs_cond_new();
    trd_ = new SrsSTCoroutine("sip-udp-sender", this);
}

SrsGbSipUDPSender::~SrsGbSipUDPSender()
{
    srs_cond_destroy(wait_);

    for (vector<SrsSipMessage*>::iterator it = msgs_.begin(); it != msgs_.end(); ++it) {
        SrsSipMessage* msg = *it;
        srs_freep(msg);
    }
}

void SrsGbSipUDPSender::enqueue(SrsSipMessage* msg)
{
    msgs_.push_back(msg);
    srs_cond_signal(wait_);
}

void SrsGbSipUDPSender::interrupt()
{
    trd_->interrupt();
}

void SrsGbSipUDPSender::set_cid(const SrsContextId& cid)
{
    trd_->set_cid(cid);
}

srs_error_t SrsGbSipUDPSender::start()
{
    srs_error_t err = srs_success;

    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "coroutine");
    }

    return err;
}

srs_error_t SrsGbSipUDPSender::cycle()
{
    srs_error_t err = do_cycle();

    // TODO: FIXME: Notify SIP transport to cleanup.
    if (err != srs_success) {
        srs_error("SIP-UDP: Send err %s", srs_error_desc(err).c_str());
    }

    return err;
}

srs_error_t SrsGbSipUDPSender::do_cycle()
{
    srs_error_t err = srs_success;

    while (true) {
        if (msgs_.empty()) {
            srs_cond_wait(wait_);
        }

        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "pull");
        }

        SrsUniquePtr<SrsSipMessage> msg(msgs_.front());
        msgs_.erase(msgs_.begin());
        SrsGbSipUdpReadWriter sip_udp_writer(skt_);
        if (msg->type_ == HTTP_RESPONSE) {
            SrsSipResponseWriter res(&sip_udp_writer);
            res.header()->set("Via", msg->via_);
            res.header()->set("From", msg->from_);
            res.header()->set("To", msg->to_);
            res.header()->set("CSeq", msg->cseq_);
            res.header()->set("Call-ID", msg->call_id_);
            res.header()->set("User-Agent", RTMP_SIG_SRS_SERVER);
            if (!msg->contact_.empty()) res.header()->set("Contact", msg->contact_);
            if (msg->expires_ != UINT32_MAX) res.header()->set("Expires", srs_int2str(msg->expires_));

            res.header()->set_content_length(msg->body_.length());
            res.write_header(msg->status_);
            if (!msg->body_.empty()) res.write((char*) msg->body_.c_str(), msg->body_.length());
            if ((err = res.final_request()) != srs_success) {
                return srs_error_wrap(err, "response");
            }
        } else if (msg->type_ == HTTP_REQUEST) {
            SrsSipRequestWriter req(&sip_udp_writer);
            req.header()->set("Via", msg->via_);
            req.header()->set("From", msg->from_);
            req.header()->set("To", msg->to_);
            req.header()->set("CSeq", msg->cseq_);
            req.header()->set("Call-ID", msg->call_id_);
            req.header()->set("User-Agent", RTMP_SIG_SRS_SERVER);
            if (!msg->contact_.empty()) req.header()->set("Contact", msg->contact_);
            if (!msg->subject_.empty()) req.header()->set("Subject", msg->subject_);
            if (msg->max_forwards_) req.header()->set("Max-Forwards", srs_int2str(msg->max_forwards_));

            if (!msg->content_type_.empty()) req.header()->set_content_type(msg->content_type_);
            req.header()->set_content_length(msg->body_.length());
            req.write_header(http_method_str(msg->method_), msg->request_uri_);
            if (!msg->body_.empty()) req.write((char*) msg->body_.c_str(), msg->body_.length());
            if ((err = req.final_request()) != srs_success) {
                return srs_error_wrap(err, "request");
            }
        } else {
            srs_warn("SIP: Sender drop message type=%d, method=%s, body=%dB", msg->type_,
                     http_method_str(msg->method_), msg->body_.length());
        }
    }

    return err;
}



SrsGbSipUdpReadWriter::SrsGbSipUdpReadWriter(SrsUdpMuxSocket *skt) {
    skt_ = skt;
    skt_sendonly_ = skt->copy_sendonly();
}

SrsGbSipUdpReadWriter::~SrsGbSipUdpReadWriter() {
    srs_freep(skt_sendonly_);
}

srs_error_t SrsGbSipUdpReadWriter::read(void *buf, size_t size, ssize_t *nread) {
    std::string str = skt_->data();
    if (str.empty()) {
        return srs_error_new(ERROR_SYSTEM_FILE_EOF, "EOF");
    }

    int len = srs_min(str.length(), size);
    if (len == 0) {
        return srs_error_new(-1, "no data");
    }

    memcpy(buf, str.data(), len);
    str = str.substr(len);

    if (nread) {
        *nread = len;
    }
    return srs_success;
}

void SrsGbSipUdpReadWriter::set_recv_timeout(srs_utime_t tm) {
}

srs_utime_t SrsGbSipUdpReadWriter::get_recv_timeout() {
}

srs_error_t SrsGbSipUdpReadWriter::read_fully(void *buf, size_t size, ssize_t *nread) {
}

int64_t SrsGbSipUdpReadWriter::get_recv_bytes() {
}

int64_t SrsGbSipUdpReadWriter::get_send_bytes() {
}

void SrsGbSipUdpReadWriter::set_send_timeout(srs_utime_t tm) {
}

srs_utime_t SrsGbSipUdpReadWriter::get_send_timeout() {
}

srs_error_t SrsGbSipUdpReadWriter::write(void *buf, size_t size, ssize_t *nwrite) {
    if (nwrite) *nwrite = size;
    return skt_sendonly_->sendto(buf, size, SRS_UTIME_NO_TIMEOUT);
}

srs_error_t SrsGbSipUdpReadWriter::writev(const iovec *iov, int iov_size, ssize_t *nwrite) {
}
