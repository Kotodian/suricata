/* Copyright (C) 2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Kotodian <blackfaceuncle@gmail.com
 *
 * File-like output for logging:  kafka
 */
#include "suricata-common.h"
#include "util-log-kafka.h"
#include "util-logopenfile.h"
#include "util-byte.h"
#include "util-debug.h"

#ifdef HAVE_LIBRDKAFKA

static const char * kafka_default_topic = "suricata";
static const char * kafka_default_server = "127.0.0.1:9092";


/**
 * \brief SCLogKafkaInit() - Initializes global stuff before threads
 */
void SCLogKafkaInit(void)
{

}

/** \brief SCLogKafkaContextAlloc() - Allocates and initializes kafka context
 */
static SCLogKafkaContext *SCLogKafkaContextAlloc(void)
{
    SCLogKafkaContext* ctx = (SCLogKafkaContext*) SCCalloc(1, sizeof(SCLogKafkaContext));
    if (ctx == NULL) {
        FatalError("Unable to allocate kafka context");
    }

    ctx->rk = NULL;

    return ctx;
}

/** \brief SCLogKafkaWriteSync() writes string to kafka output
 *  \param file_ctx Log file context allocated by caller
 *  \param string Buffer to output
 */
static int SCLogKafkaWrite(LogFileCtx *file_ctx, const char *string, size_t string_len)
{
    SCLogKafkaContext *ctx = file_ctx->kafka;
    rd_kafka_resp_err_t err;

    if (string_len == 0) {
        rd_kafka_poll(ctx->rk, 0);
        return 0;
    }

retry:
    err = rd_kafka_producev(
        /* Producer Handle */
        ctx->rk,
        /* Topic name */
        RD_KAFKA_V_TOPIC(file_ctx->kafka_setup.topic),
        /* Make a copy of the payload */ 
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        /* Message value and length */
        RD_KAFKA_V_VALUE(string, string_len),
        /* Per-Message opaque, provided in 
         * delivery report callback as
         * msg_opaque. */
        RD_KAFKA_V_OPAQUE(NULL),
        /* End sentinel */
        RD_KAFKA_V_END);

    if (err) {
        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            rd_kafka_poll(ctx->rk, 1000 /*block for max 1000ms*/);
            goto retry;
        }
        SCLogError("Unable to produce message %s", rd_kafka_err2str(err));
        return -1;
    }

    rd_kafka_poll(ctx->rk, 0);

    return 0;
}

/**
 * \brief LogFileWriteKafka() writes log data to kafka output.
 * \param log_ctx Log file context allocated by caller
 * \param string buffer with data to write
 * \param string_len data length
 * \retval 0 on success;
 * \retval -1 on failure;
 */
int LogFileWriteKafka(void *lf_ctx, const char *string, size_t string_len)
{
    LogFileCtx *file_ctx = lf_ctx;
    if (file_ctx == NULL) {
        return -1;
    }
    return SCLogKafkaWrite(file_ctx, string, string_len);
}

/**
 * \brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was succesfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll() and executes on
 * the application's thread.
 */
static void
DrMsgCb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        /* The rkmessage is destroyed automatically by librdkafka */
}

/** \brief SCLogFileCloseKafka() Closes kafka log more
 *  \param log_ctx Log file context allocated by caller
 */
void SCLogFileCloseKafka(LogFileCtx *log_ctx)
{
    SCLogKafkaContext * ctx = log_ctx->kafka;
    if (ctx == NULL) {
        return;
    }

    rd_kafka_flush(ctx->rk, 1 * 1000); /* wait for max 1 seconds */

    rd_kafka_destroy(ctx->rk);

    if (ctx != NULL) {
        SCFree(ctx);
    }
}

/** \brief configure and initializes kafka output logging
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \retval 0 on success
 */
int SCConfLogOpenKafka(ConfNode *kafka_node, void *lf_ctx)
{
    LogFileCtx *log_ctx = lf_ctx;
    SCLogKafkaContext *ctx;
    rd_kafka_t *rk;
    rd_kafka_conf_t *conf;
    char errstr[512];

    if (log_ctx->threaded) {
        FatalError("kafka does not support threaded output");
    }

    if (kafka_node) {
        log_ctx->kafka_setup.server = ConfNodeLookupChildValue(kafka_node, "server");
        log_ctx->kafka_setup.topic = ConfNodeLookupChildValue(kafka_node, "topic");
    }

    if (!log_ctx->kafka_setup.server) {
        log_ctx->kafka_setup.server = kafka_default_server;
        SCLogInfo("Using default kafka server (127.0.0.1)");
    }

    if (!log_ctx->kafka_setup.topic) {
        log_ctx->kafka_setup.topic = kafka_default_topic; 
    }

    conf = rd_kafka_conf_new();

    if (rd_kafka_conf_set(conf, "bootstrap.servers", log_ctx->kafka_setup.server, errstr,
                            sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        FatalError("kafka conf set failed");
    }

    rd_kafka_conf_set_dr_msg_cb(conf, DrMsgCb);

    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk) {
        FatalError("kafka new failed");
    }

    ctx = SCLogKafkaContextAlloc();
    ctx->rk = rk;

    log_ctx->kafka = ctx;
    log_ctx->Close = SCLogFileCloseKafka;

    return 0;
}

#endif //#ifdef HAVE_LIBRDKAFKA
