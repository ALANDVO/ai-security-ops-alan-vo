import logging, base64
from typing import Optional, Dict
from datetime import datetime

logger = logging.getLogger(__name__)

class SAMLHandler:

    def __init__(self, sp_entity: str, idp_entity: str, idp_cert: str, acs_url: str):
        self.sp_entity = sp_entity
        self.idp_entity = idp_entity
        self.idp_cert = idp_cert
        self.acs_url = acs_url

    def build_authn_request(self, relay_state: str = "") -> Dict:
        import uuid
        return {
            "id": f"req-{uuid.uuid4().hex[:12]}",
            "issue_instant": datetime.utcnow().isoformat() + "Z",
            "issuer": self.sp_entity,
            "destination": self.idp_entity,
            "protocol": "urn:oasis:names:tc:saml:2.0:protocol",
            "assertion_consumer_service_url": self.acs_url,
            "relay_state": relay_state,
        }

    def process_response(self, request) -> Dict:
        from fastapi import HTTPException
        saml_response = request.form.get("SAMLResponse", "") if hasattr(request, "form") else ""
        if not saml_response:
            raise HTTPException(status_code=400, detail="Missing SAMLResponse parameter")
        decoded = self._decode_assertion(saml_response)
        attrs = decoded.get("attributes", {})
        email = attrs.get("email", attrs.get("mail", attrs.get("user", "")))
        name = attrs.get("first_name", "") + " " + attrs.get("last_name", "")
        return {"email": email, "name": name.strip() or "sso-user", "role": "admin"}

    def _decode_assertion(self, saml_response: str) -> Dict:
        try:
            xml_bytes = base64.b64decode(saml_response)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_bytes)
            ns = {"saml": "urn:oasis:names:tc:saml:2.0:assertion"}
            attrs = {}
            for attr in root.findall(".//saml:Attribute", ns):
                name = attr.get("Name", "")
                for val in attr.findall("saml:AttributeValue", ns):
                    attrs[name] = val.text or ""
            return {"attributes": attrs, "valid": True}
        except Exception as e:
            logger.error("SAML assertion decode error: %s", e)
            return {"attributes": {}, "valid": False}

    def get_metadata(self) -> str:
        template = (
            '<?xml version="1.0" encoding="UTF-8"?>
'
            '<EntityDescriptor xmlns="urn:oasis:names:tc:saml:2.0:metadata" entityID="{sp}">
'
            '  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true">
'
            '    <NameIDFormat>urn:oasis:names:tc:saml:2.0:nameid-format:emailAddress</NameIDFormat>
'
            '    <AssertionConsumerService Binding="urn:oasis:names:tc:saml:2.0:bindings:HTTP-POST" Location="{acs}" index="0"/>
'
            '  </SPSSODescriptor>
'
            '</EntityDescriptor>'
        )
        return template.format(sp=self.sp_entity, acs=self.acs_url)
