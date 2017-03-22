# with open('/home/dr/Desktop/dworkspace/debug.txt', 'w') as fd:
#     fd.write('dr2')
from intelmq.bin import intelmqctl
from intelmq.bots.parsers.test_by_dr import parser_csv


# x.run()
# x.bot_run(bot_id='malware-domain-list-parser')
# x.list(kind='queues')
# x.bot_run(bot_id='abusech-feodo-domains-collector')

# x.bot_run(bot_id='malware-domain-list-collector')
# x.bot_run(bot_id='malware-domain-list-parser')
# x.bot_run(bot_id='file-output')

x = intelmqctl.IntelMQController(interactive=True)
x.bot_start(bot_id='malware-domain-list-parser')

# x = parser_csv.test()
# x.f1()
