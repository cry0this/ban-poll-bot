#!/usr/bin/env python3

import argparse
import aiohttp
import datetime
import discord
import sys
import traceback
import warnings

from discord.ext import commands
from functools import wraps

from ban_poll_bot.config import DISCORD_PREFIX, DISCORD_TOKEN_PATH, LOG_PATH, LIMITS, \
    ADMIN_PERMISSIONS, DEFAULT_TIMEOUT_HOURS
from ban_poll_bot.logger import get_logger


logger = get_logger('ban_poll_bot')

warnings.filterwarnings("ignore", category=DeprecationWarning)
intents = discord.Intents.all()
bot = commands.Bot(command_prefix=DISCORD_PREFIX, help_command=None)
bot.session = aiohttp.ClientSession()

user_votes= {}


def main_decorator(fn):
    def get_full_class_name(obj):
        module = obj.__class__.__module__

        if module is None or module == str.__class__.__module__:
            return obj.__class__.__name__

        return module + '.' + obj.__class__.__name__

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            logger.error("{}: {}\nTraceback:\n{}".format(
                get_full_class_name(e), str(e), ''.join(traceback.format_tb(e.__traceback__))
            ))

            die()

        return result

    return wrapper


def die():
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description='Discord bot for ban/kick/mute user by poll')

    parser.add_argument(
        '-l', '--log-path',
        default=LOG_PATH,
        help='log path'
    )

    parser.add_argument(
        '-t', '--token-path',
        default=DISCORD_TOKEN_PATH,
        help='path to file with token'
    )

    return parser.parse_args()


def is_user_admin(user) -> bool:
    return any([
        getattr(user.guild_permissions, permission) for permission in ADMIN_PERMISSIONS
    ])


async def timeout_user(*, user_id: int, guild_id: int, until):
    headers = {"Authorization": f"Bot {bot.http.token}"}
    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}"
    timeout = (datetime.datetime.utcnow() + datetime.timedelta(minutes=until)).isoformat()
    json = {'communication_disabled_until': timeout}

    async with bot.session.patch(url, json=json, headers=headers) as session:
        logger.debug(session.status)
        logger.debug(session.text)
        if session.status in range(200, 299):
           return True
        return False


@bot.command()
async def help(ctx):
    help_msg = """
**Список команд**

> `banpoll.help` - получить данную справку
> `banpoll.kick @username` - выгнать юзера
> `banpoll.ban @username` - забанить юзера
> `banpoll.mute @username` - замьютить юзера на {} {}
> `banpoll.flush @username` - обнулить голоса за юзера
> `banpoll.votes @username` - посмотреть голоса за юзера

""".format(
    DEFAULT_TIMEOUT_HOURS,
    'час' if DEFAULT_TIMEOUT_HOURS == 1 else ('часа' if DEFAULT_TIMEOUT_HOURS < 5 else 'часов')
)
    await ctx.send(help_msg)


@bot.command()
async def test(ctx, *args):
    await ctx.send(args)


@bot.command()
async def kick(ctx, member: discord.Member):
    logger.info("got kick command for user {}:{} from {}:{}".format(
        member.name, member.id,
        ctx.author.name, ctx.author.id
    ))

    if ctx.author.id == member.id:
        await ctx.send(f"<@{member.id}> сам себя кикнуть пытаешься, наркоман?")
        return

    if member.bot:
        await ctx.send("<@{}> пытаешься бота кикнуть, хитрец?".format(ctx.author.id))
        return

    if member.id == ctx.guild.owner_id:
        await ctx.send("<@{}> пытаешься кикнуть владельца сервера? Совсем дебил?".format(ctx.author.id))
        return

    if is_user_admin(member):
        await ctx.send("<@{}> пытаешься кикнуть админа/модера? С тобой всё хорошо?".format(ctx.author.id))
        return

    if member.id not in user_votes:
        user_votes[member.id] = {}

    if 'kick' not in user_votes[member.id]:
        user_votes[member.id]['kick'] = []


    if ctx.author.id in user_votes[member.id]['kick']:
        await ctx.send("<@{}> ты уже голосовал за изгнание <@{}>".format(
            ctx.author.id, member.id ))
        return

    user_votes[member.id]['kick'].append(ctx.author.id)

    votes_left = LIMITS['kick'] - len(user_votes[member.id]['kick'])

    await ctx.send("Пользователь <@{}> получил голос за изгнание. Еще {} {} осталось.".format(
        member.id,
        votes_left,
        'голос' if votes_left == 1 else ('голоса' if votes_left < 5 else 'голосов')
    ))

    if len(user_votes[member.id]['kick']) >= LIMITS['kick']:
        logger.info(f"user {member.id}:{member.name} kicked")
        await ctx.send(f"Пользователь <@{member.id}> изгнан")
        await ctx.guild.kick(member, reason="Выгнан через бота голосованием")
        return


@bot.command()
async def ban(ctx, member: discord.Member):
    logger.info("got ban command for user {}:{} from {}:{}".format(
        member.name, member.id,
        ctx.author.name, ctx.author.id
    ))

    if ctx.author.id == member.id:
        await ctx.send(f"<@{member.id}> сам себя забанить пытаешься, наркоман?")
        return

    if member.bot:
        await ctx.send("<@{}> пытаешься бота забанить, хитрец?".format(ctx.author.id))
        return

    if member.id == ctx.guild.owner_id:
        await ctx.send("<@{}> пытаешься забанить владельца сервера? Совсем дебил?".format(ctx.author.id))
        return

    if is_user_admin(member):
        await ctx.send("<@{}> пытаешься забанить админа/модера? С тобой всё хорошо?".format(ctx.author.id))
        return

    if member.id not in user_votes:
        user_votes[member.id] = {}

    if 'ban' not in user_votes[member.id]:
        user_votes[member.id]['ban'] = []

    if ctx.author.id in user_votes[member.id]['ban']:
        await ctx.send("<@{}> ты уже голосовал за бан <@{}>".format(
            ctx.author.id, member.id ))
        return

    user_votes[member.id]['ban'].append(ctx.author.id)

    votes_left = LIMITS['ban'] - len(user_votes[member.id]['ban'])

    await ctx.send("Пользователь <@{}> получил голос за бан. Еще {} {} осталось.".format(
        member.id,
        votes_left,
        'голос' if votes_left == 1 else ('голоса' if votes_left < 5 else 'голосов')
    ))

    if len(user_votes[member.id]['ban']) >= LIMITS['ban']:
        logger.info(f"user {member.id}:{member.name} banned")
        await ctx.send(f"Пользователь <@{member.id}> забанен")
        await ctx.guild.ban(member, reason="Забанен через бота голосованием")
        return


@bot.command()
async def mute(ctx, member: discord.Member):
    logger.info("got mute command for user {}:{} from {}:{}".format(
        member.name, member.id,
        ctx.author.name, ctx.author.id
    ))

    if ctx.author.id == member.id:
        await ctx.send(f"<@{member.id}> сам себя замьютить пытаешься, наркоман?")
        return

    if member.bot:
        await ctx.send("<@{}> пытаешься бота замьютить, хитрец?".format(ctx.author.id))
        return

    if member.id == ctx.guild.owner_id:
        await ctx.send("<@{}> пытаешься замьютить владельца сервера? Совсем дебил?".format(ctx.author.id))
        return

    if is_user_admin(member):
        await ctx.send("<@{}> пытаешься замьютить админа/модера? С тобой всё хорошо?".format(ctx.author.id))
        return

    if member.id not in user_votes:
        user_votes[member.id] = {}

    if 'mute' not in user_votes[member.id]:
        user_votes[member.id]['mute'] = []

    if ctx.author.id in user_votes[member.id]['mute']:
        await ctx.send("<@{}> ты уже голосовал за мьют <@{}>".format(
            ctx.author.id, member.id ))
        return

    user_votes[member.id]['mute'].append(ctx.author.id)

    votes_left = LIMITS['mute'] - len(user_votes[member.id]['mute'])

    if len(user_votes[member.id]['mute']) >= LIMITS['mute']:
        timeout = DEFAULT_TIMEOUT_HOURS * 60

        handshake = await timeout_user(user_id=member.id, guild_id=ctx.guild.id, until=timeout)
        if handshake:
            logger.info(f"user {member.name}:{member.id} muted")
            await ctx.send("Пользователь <@{}> замьючен на {} {}".format(
                member.id, DEFAULT_TIMEOUT_HOURS,
                'час' if DEFAULT_TIMEOUT_HOURS == 1 else ('часа' if DEFAULT_TIMEOUT_HOURS < 5 else 'часов')
            ))

        else:
            logger.error("failed to mute user {}:{} : {}".format(
                member.name, member.id,
                handshake
            ))
            await ctx.send("Упс, что-то пошло не так")

        return

    await ctx.send("Пользователь <@{}> получил голос за мьют. Еще {} {} осталось.".format(
        member.id,
        votes_left,
        'голос' if votes_left == 1 else ('голоса' if votes_left < 5 else 'голосов')
    ))


@bot.command()
async def flush(ctx, member: discord.Member):
    logger.info("got flush command for user {}:{} from {}:{}".format(
        member.name, member.id,
        ctx.author.name, ctx.author.id
    ))

    if not is_user_admin(ctx.author):
        await ctx.send("<@{}> данная команда доступна только модерам/админам".format(ctx.author.id))
        return

    if member.id not in user_votes:
        await ctx.send(f"У пользователя <@{member.id}> нет голосов. Нечего делать")
        return

    user_votes.pop(member.id)

    logger.info("votes for user {}:{} flushed".format(member.name, member.id))
    await ctx.send(f"Голоса для пользователя <@{member.id}> удалены")


@bot.command()
async def votes(ctx, user: discord.User):
    if user.id not in user_votes:
        await ctx.send(f"Голосов за <@{user.id}> не найдено")
        return

    msg = []
    for key in user_votes[user.id]:
        msg.append("{}: {}, limit: {}".format(
            key,
            len(user_votes[user.id][key]),
            LIMITS[key]
        ))

    await ctx.send("Голоса за <@{}>:\n```\n{}\n```".format(
        user.id, '\n'.join(msg)
    ))


@main_decorator
def main():
    args = parse_args()
    logger.init_file_handler(args.log_path)

    with open(args.token_path, 'r') as f:
        discord_token = f.read().strip()

    if not discord_token:
        logger.error(f"got empty token from '{args.token_path}'")
        die()

    bot.run(discord_token)


if __name__ == '__main__':
    main()
