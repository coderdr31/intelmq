# with open('/home/dr/Desktop/dworkspace/debug.txt', 'w') as fd:
#     fd.write('dr2')
from intelmq.bin import intelmqctl

x = intelmqctl.IntelMQController(interactive=True)
# x.run()
# x.bot_run(bot_id='malware-domain-list-parser')
# x.list(kind='queues')
# x.bot_run(bot_id='abusech-feodo-domains-collector')

# x.bot_run(bot_id='malware-domain-list-collector')
x.bot_run(bot_id='malware-domain-list-parser')