FROM wazuh/wazuh-manager:4.7.2

COPY config/local_rules.xml /var/ossec/etc/rules/
COPY config/decoders/custom_decoders.xml /var/ossec/etc/decoders/

RUN chown -R wazuh:wazuh /var/ossec/etc/
