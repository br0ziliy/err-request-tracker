import re
import requests
from requests_kerberos import HTTPKerberosAuth

from itertools import chain
from errbot.utils import ValidationException
from errbot import BotPlugin, botcmd, re_botcmd

CONFIG_TEMPLATE = {'USER': '',
                   'PASSWORD': '',
                   'REST_URL': '',
                   'DISPLAY_URL': '',
                   'MINIMUM_TICKET_ID': 1}


class RT(BotPlugin):
    """Request Tracker plugin for Err"""

    tracker = None
    re_find_ticket = r'(^| |(https?\:\/\/.+=)|rt)#?(\d{1,})( |\?|\.|,|:|\!|$)'

    def get_configuration_template(self):
        return CONFIG_TEMPLATE

    def configure(self, configuration):
        if configuration is not None and configuration != {}:
            config = dict(chain(CONFIG_TEMPLATE.items(),
                                configuration.items()))
        else:
            config = CONFIG_TEMPLATE

        super(RT, self).configure(config)

    def check_configuration(self, config):

        self.tracker = False

        for key in ['REST_URL', 'DISPLAY_URL', 'USER', 'PASSWORD']:

            if key not in config:
                raise ValidationException("missing config value: " + key)

    @re_botcmd(pattern=re_find_ticket, prefixed=False, flags=re.IGNORECASE)
    def find_ticket(self, message, match):
        """ Look up ticket metadata (works without prefix). Example: 12345 """
        url = match.group(2)
        ticket = match.group(3)
        self.log.debug("Match: {}".format(match))
        self.log.debug("URL: {}".format(url))
        self.log.debug("Ticket: {}".format(ticket))

        if url and url != self.config['DISPLAY_URL']:
            return

        if int(ticket) >= self.config['MINIMUM_TICKET_ID']:
            return self.ticket_summary(ticket)

    def ticket_summary(self, ticket_id):

        try:
            response = requests.get("".join([self.config['REST_URL'], 'ticket/', ticket_id]),auth=HTTPKerberosAuth())
            self.log.debug(response)
            subject = 'No subject'
            owner = 'Nobody'
            queue = 'unknown'
            requestors = 'Nobody'
            url = "".join([self.config['DISPLAY_URL'], ticket_id])
            if response.status_code == 200:
                    for line in response.text.split('\n'):
                      if   line.startswith("Owner:"):   owner = line.split(":")[1].rstrip()
                      elif line.startswith("Subject:"): subject = line.split(":")[1].rstrip()
                      elif line.startswith("Queue:"):   queue = line.split(":")[1].rstrip()
                      elif line.startswith("Requestors:"): requestors = line.split(":")[1].rstrip()
                      else: next
                    return "[{}]({}) - {} - {}".format(subject, url, queue, requestors)
            else:
                    return "Hmm..."
        except:
            return "Sorry, that ticket does not exist or I cannot access it."
