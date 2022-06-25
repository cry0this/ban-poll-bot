DISCORD_PREFIX = 'banpoll.'
DISCORD_TOKEN_PATH = 'token.txt'

LOG_PATH = '/var/log/ban_poll_bot.log'

LIMITS = {
    'kick': 5,
    'ban': 10,
    'mute': 3,
}

ADMIN_PERMISSIONS = [
    'administrator',
    'ban_members',
    'kick_members',
    'mute_members',
]

DEFAULT_TIMEOUT_HOURS = 1
