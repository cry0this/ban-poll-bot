PREFIX = '!banpoll '

LOG_PATH = '/var/log/ban_poll_bot.log'

LIMITS = {
    'kick': 10,
    'ban': 15,
    'mute': 5,
}

ADMIN_PERMISSIONS = [
    'administrator',
    'ban_members',
    'kick_members',
    'mute_members',
]

DEFAULT_TIMEOUT_HOURS = 4

RU_DICT = {
    'kick': 'изгнание',
    'ban': 'бан',
    'mute': 'таймаут'
}

HELP_STRINGS = [
    '> `{}help` - получить данную справку',
    '> `{}kick @username` - выгнать юзера',
    '> `{}ban @username` - забанить юзера',
    '> `{}mute @username` - замьютить юзера',
    '> `{}flush @username` - обнулить голоса за юзера',
    '> `{}votes @username` - посмотреть голоса за юзера'
]
