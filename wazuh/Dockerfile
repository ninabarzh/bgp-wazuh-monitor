FROM wazuh/wazuh-manager:4.7.2

COPY config/local_rules.xml /var/ossec/etc/rules/
RUN chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml