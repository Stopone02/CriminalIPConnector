import os
import sys
import yaml
import requests
from typing import Dict, Any, List

from stix2 import (
    IPv4Address,
    AutonomousSystem,
    Location,
    Indicator,
    Bundle,
)
from pycti import OpenCTIConnectorHelper, get_config_variable


class CriminalIPConnector:
    """
    Criminal IP Enrichment Connector
    """

    def __init__(self):
        """
        Initialize the CriminalIPConnector with necessary configurations
        """
        # Load configuration
        config_file_path = os.path.join(
            os.path.dirname(__file__), "config.yml"
        )
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        # Initialize OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config)

        # Get Criminal IP API Key
        self.api_key = get_config_variable(
            "CRIMINALIP_TOKEN", ["criminalip", "api_key"], config
        )
        if self.api_key is None:
            msg = "Criminal IP API key is not set."
            self.helper.log_error(msg)
            raise ValueError(msg)
        
        self.base_url = "https://api.criminalip.io/v1"

    def _call_api(self, endpoint: str, ip: str) -> Dict[str, Any]:
        """A helper method to call the Criminal IP API"""
        url = f"{self.base_url}{endpoint}"
        headers = {"x-api-key": self.api_key}
        params = {"ip": ip}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Error calling Criminal IP API for {ip}: {e}")
            return None
    
    def _to_stix_objects(self, ip_data: Dict[str, Any]) -> List[Any]:
        """Convert Criminal IP API response to a list of STIX objects"""
        
        # 먼저 재사용할 표준 객체들의 ID를 가져옵니다.
        try:
            # 최신 필터 형식으로 수정 (filterGroups 사용)
            tlp_clear_filter = {
                "mode": "and",
                "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}],
                "filterGroups": [],
            }
            tlp_marking = self.helper.api.marking_definition.read(filters=tlp_clear_filter)
            if not tlp_marking:
                self.helper.log_error("Could not find TLP:CLEAR marking definition.")
                return []
            tlp_id = tlp_marking['standard_id']
            
            # 최신 필터 형식으로 수정 (filterGroups 사용)
            identity_filter = {
                "mode": "and",
                "filters": [{"key": "name", "values": ["CriminalIPConnector"]}],
                "filterGroups": [],
            }
            identity = self.helper.api.identity.read(filters=identity_filter)
            if identity is None:
                # ID가 없으면 커넥터 ID로 생성
                identity = self.helper.api.identity.create(
                    type="Organization",
                    name="CriminalIP Connector",
                    description="Connector for Criminal IP threat intelligence."
                )
            identity_id = identity['standard_id']
        except Exception as e:
            self.helper.log_error(f"Error getting standard object IDs: {e}")
            return []

        objects = []
        ip_value = ip_data.get("ip")
        if not ip_value:
            return []

        # Create IPv4Address object first as a foundation
        ipv4_addr_stix = IPv4Address(value=ip_value)
        objects.append(ipv4_addr_stix)

        # Create Indicator for Score
        score = ip_data.get("score", {})
        inbound = score.get("inbound")
        outbound = score.get("outbound")
        if inbound is not None or outbound is not None:
            confidence = max(int(inbound or 0), int(outbound or 0))
            labels = []
            if inbound is not None:
                labels.append(f"criminalip-inbound-score:{inbound}")
            if outbound is not None:
                labels.append(f"criminalip-outbound-score:{outbound}")
            
            indicator_score = Indicator(
                name=f"Criminal IP Reputation for {ip_value}",
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip_value}']",
                confidence=confidence,
                labels=labels,
                object_marking_refs=[tlp_id],
                created_by_ref=identity_id
            )
            objects.append(indicator_score)

        # Create Indicator for Tags
        tags = ip_data.get("tags", {})
        tag_labels = [k.replace("is_", "").upper() for k, v in tags.items() if isinstance(v, bool) and v]
        if tag_labels:
            indicator_tags = Indicator(
                name=f"Criminal IP Tags for {ip_value}",
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip_value}']",
                labels=tag_labels,
                object_marking_refs=[tlp_id],
                created_by_ref=identity_id
            )
            objects.append(indicator_tags)

        # Create AS and Location
        if ip_data.get("asn"):
            as_stix = AutonomousSystem(number=ip_data.get("asn"))
            objects.append(as_stix)
        if ip_data.get("country_code"):
            loc_stix = Location(country=ip_data.get("country_code"))
            objects.append(loc_stix)

        return objects
    # def _to_stix_objects(self, ip_data: Dict[str, Any]) -> List[Any]:
    #     """Convert Criminal IP API response to a list of STIX objects"""
    #     objects = []
    #     ip_value = ip_data.get("ip")
    #     if not ip_value:
    #         return []

    #     # Create IPv4Address object first as a foundation
    #     ipv4_addr_stix = IPv4Address(value=ip_value)
    #     objects.append(ipv4_addr_stix)

    #     # Create Indicator for Score
    #     score = ip_data.get("score", {})
    #     inbound = score.get("inbound")
    #     outbound = score.get("outbound")
    #     if inbound is not None or outbound is not None:
    #         confidence = max(int(inbound or 0), int(outbound or 0))
    #         labels = []
    #         if inbound is not None:
    #             labels.append(f"criminalip-inbound-score:{inbound}")
    #         if outbound is not None:
    #             labels.append(f"criminalip-outbound-score:{outbound}")
            
    #         indicator_score = Indicator(
    #             name=f"Criminal IP Reputation for {ip_value}",
    #             pattern_type="stix",
    #             pattern=f"[ipv4-addr:value = '{ip_value}']",
    #             confidence=confidence,
    #             labels=labels,
    #             object_marking_refs=[self.helper.api.marking_definition.get_id_by_definition("TLP:WHITE")],
    #             created_by_ref=self.helper.api.identity.get_id_by_name("CriminalIP Connector")
    #         )
    #         objects.append(indicator_score)

    #     # Create Indicator for Tags
    #     tags = ip_data.get("tags", {})
    #     tag_labels = [k.replace("is_", "").upper() for k, v in tags.items() if isinstance(v, bool) and v]
    #     if tag_labels:
    #         indicator_tags = Indicator(
    #             name=f"Criminal IP Tags for {ip_value}",
    #             pattern_type="stix",
    #             pattern=f"[ipv4-addr:value = '{ip_value}']",
    #             labels=tag_labels,
    #             object_marking_refs=[self.helper.api.marking_definition.get_id_by_definition("TLP:WHITE")],
    #             created_by_ref=self.helper.api.identity.get_id_by_name("CriminalIP Connector")
    #         )
    #         objects.append(indicator_tags)

    #     # Create AS and Location
    #     if ip_data.get("asn"):
    #         as_stix = AutonomousSystem(number=ip_data.get("asn"))
    #         objects.append(as_stix)
    #     if ip_data.get("country_code"):
    #         loc_stix = Location(country=ip_data.get("country_code"))
    #         objects.append(loc_stix)

    #     return objects

    def _process_message(self, data):
        """Main method to process a message from the bus"""
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        
        if observable is None:
            self.helper.log_error(f"Observable not found with id {entity_id}.")
            return "Observable not found"

        # OpenCTI 버전에 따라 'value' 또는 'observable_value' 키를 사용하므로, 둘 다 확인
        ip_to_enrich = observable.get("value") or observable.get("observable_value")

        if not ip_to_enrich:
            self.helper.log_error(f"Could not find IP value in observable: {observable}")
            return "IP value not found in observable."

        self.helper.log_info(f"Processing IP: {ip_to_enrich}")

        # Call Criminal IP API
        ip_data = self._call_api("/ip/data", ip_to_enrich)
        if not ip_data:
            return f"Could not retrieve data for {ip_to_enrich} from Criminal IP."
        
        self.helper.log_info(f"IP Data: {ip_data}")

        # Convert to STIX objects
        stix_objects = self._to_stix_objects(ip_data)
        if not stix_objects:
            return f"No STIX objects created for {ip_to_enrich}."
        
        self.helper.log_info(f"STIX Objects: {stix_objects}")
        
        # Create a bundle and send it to OpenCTI
        bundle = Bundle(objects=stix_objects, allow_custom=True).serialize()
        result = self.helper.send_stix2_bundle(bundle, entity_id=observable.get("id"))

        self.helper.log_info(f"Successfully enriched IP {ip_to_enrich}.")
        self.helper.log_info(f"Bundle sent. Result: {result}")
        return "Success"

    def start(self):
        """Start the connector"""
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = CriminalIPConnector()
        connector.start()
    except Exception as e:
        print(e)
        sys.exit(1)