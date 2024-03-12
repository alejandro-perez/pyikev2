class EAPClient:
    def __init__(self, config):
        self.config = config

    def handleMessage(self, eap_message):
        print("handle EAP message")
        return False
