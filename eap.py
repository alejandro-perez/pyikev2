from scapy.layers.eap import EAP, EAP_TLS
import logging
from time import sleep

class EAPClient:
    def __init__(self, config, eapTlsClientSocket = None):
        self.config = config
        self.running = False
        self.tlsStarted = False
        self.eapTlsClientSocket = eapTlsClientSocket
        self.lastId = None
        self.lastReply = None

    def stop(self):
        if self.eapTlsClientSocket is not None:
            self.eapTlsClientSocket.close()
            self.eapTlsClientSocket = None

    def log_msg(self, level, message):
        logging.log(level, f'EAP: {message}')

    def log_error(self, message):
        self.log_msg(logging.ERROR, message)

    def log_info(self, message):
        self.log_msg(logging.INFO, message)

    def log_warning(self, message):
        self.log_msg(logging.WARNING, message)

    def log_debug(self, message):
        self.log_msg(logging.DEBUG, message)

    def handleMessage(self, eap_message):
        eap_message = EAP(eap_message)
        if eap_message.id == self.lastId:
            self.log_debug("EAP message repeated")
            return self.lastReply

        self.lastReply = self._handleMessage(eap_message)
        self.lastId = eap_message.id

        return self.lastReply

    def _handleMessage(self, eap_message):
        self.running = True
        if eap_message.code == EAP.REQUEST:
            return self.handleRequest(eap_message).build()
        elif eap_message.code == EAP.SUCCESS:
            self.running = False
            self.log_debug("SUCCESS")
            if self.eapTlsClient is not None:
                self.eapTlsClient.close()
            return True
        elif eap_message.code == EAP.FAILURE:
            self.running = False
            self.log_debug("FAILURE")
            if self.eapTlsClient is not None:
                self.eapTlsClient.close()
            return False
        else:
            raise Exception(f"Unsupported EAP packet code {eap_message.code}")

    def handleRequest(self, eap_request):

        if eap_request.type == 1:
            # identity request
            self.log_debug("handle identity request")
            return EAP(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type) / self.config.get("identity")
        elif eap_request.type == 13 and self.eapTlsClientSocket is not None:
            if eap_request.S == 1:
                self.log_debug("Start EAP-TLS")
                assert(self.tlsStarted == False)
                self.tlsStarted = True
            assert(self.tlsStarted == True)

            if len(eap_request.tls_data) > 0:
                self.log_debug(f"writing {len(eap_request.tls_data)} bytes to eapTlsClient")
                self.eapTlsClientSocket.sendall(eap_request.tls_data)

            self.log_debug(eap_request)
            self.log_debug(f"M={eap_request.M}")
            if eap_request.M == 0:
                self.log_debug("Reading from eapTlsClient")
                # no more data from EAP peer
                # wait for reply from eapTlsClientSocket
                self.eapTlsClientSocket.settimeout(None) # wait infinity for first data back
                fromTlsClient = b""
                while (True):
                    try:
                        data = self.eapTlsClientSocket.recv(4096)
                    except TimeoutError:
                        data = b""
                    self.log_debug(f"got {len(data)} bytes")
                    if len(data) == 0:
                        self.log_debug("Receiving done")
                        break
                    fromTlsClient += data
                    self.eapTlsClientSocket.settimeout(0.05) # wait only small time to see if more data comes in
                
                if len(fromTlsClient) == 0:
                    self.log_warning("Received no reply from eapTlsClient")
                self.log_debug(f"EAP_TLS reply having {len(fromTlsClient)} bytes")
                return EAP_TLS(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type, L=1, M=0, S=0, tls_message_len=len(fromTlsClient), tls_data=fromTlsClient)
            else:
                self.log_debug("Waiting for more EAP TLS messages")
                # returning EAP_TLS message with empty EAP message
                return EAP_TLS(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type, L=0, M=0, S=0, tls_data=b"")

            
        else:
            self.log_debug(type(eap_request))
            self.log_debug(eap_request)
            
            raise Exception(f"Unsupported EAP request type {eap_request.type}")
