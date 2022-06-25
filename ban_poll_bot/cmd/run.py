#!/usr/bin/env python3

import argparse
import aiohttp
import datetime
import discord
import os
import sys
import traceback
import warnings

from discord.ext import commands
from functools import wraps

from ban_poll_bot.config import PREFIX, LOG_PATH, LIMITS, HELP_STRINGS, \
    ADMIN_PERMISSIONS, DEFAULT_TIMEOUT_HOURS, RU_DICT
from ban_poll_bot.logger import get_logger


logger = get_logger('ban_poll_bot')

warnings.filterwarnings("ignore", category=DeprecationWarning)
intents = discord.Intents.all()
bot = commands.Bot(command_prefix=PREFIX, help_command=None)
bot.session = aiohttp.ClientSession()

user_votes = {}


def die():
    sys.exit(1)


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


def parse_args():
    parser = argparse.ArgumentParser(description='Discord bot for ban/kick/mute user by poll')

    parser.add_argument(
        '-l', '--log-path',
        default=LOG_PATH,
        help='log path'
    )

    return parser.parse_args()


def is_user_admin(user: discord.Member) -> bool:
    return any([
        getattr(user.guild_permissions, permission) for permission in ADMIN_PERMISSIONS
    ])


async def check_action(action: str, ctx: commands.Context, member: discord.Member) -> bool:
    logger.info("got '{}' command for {}:{} from {}:{}".format(
        action,
        member.name, member.id,
        ctx.author.name, ctx.author.id
    ))

    if ctx.author.id == member.id:
        await ctx.send(f"<@{member.id}> ты сам себя указал, наркоман")
        return False

    if member.bot:
        await ctx.send("<@{}> ты бота указал, хитрец?".format(ctx.author.id))
        return False

    if member.id == ctx.guild.owner_id:
        await ctx.send("<@{}> ты указал владельца сервера. Совсем дебил?".format(ctx.author.id))
        return False

    if is_user_admin(member):
        await ctx.send("<@{}> ты указал админа/модера. С тобой всё хорошо?".format(ctx.author.id))
        return False

    if member.id not in user_votes:
        user_votes[member.id] = {}

    if action not in user_votes[member.id]:
        user_votes[member.id][action] = []

    if ctx.author.id in user_votes[member.id][action]:
        await ctx.send("<@{}> ты уже голосовал за <@{}>".format(
            ctx.author.id, member.id
        ))
        return False

    user_votes[member.id][action].append(ctx.author.id)
    votes_left = LIMITS[action] - len(user_votes[member.id][action])

    await ctx.send("Пользователь <@{}> получил голос за {}. Еще {} {} осталось.".format(
        member.id,
        RU_DICT[action],
        votes_left,
        'голос' if votes_left == 1 else ('голосов' if votes_left > 5 or votes_left == 0 else 'голоса')
    ))

    if len(user_votes[member.id][action]) >= LIMITS[action]:
        return True

    return False


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
    help_msg = "**Список команд**\n"
    help_msg += '\n'.join(x.format(PREFIX) for x in HELP_STRINGS)
    await ctx.send(help_msg)


@bot.command()
async def kick(ctx: commands.Context, member: discord.Member) -> None:
    if not await check_action('kick', ctx, member):
        return

    await ctx.guild.kick(member, reason="Выгнан пользовотелями через голосование")
    await ctx.send(f"Пользователь <@{member.id}> выгнан с сервера")
    logger.info(f"user {member.name}:{member.id} kicked")
    user_votes.pop(member.id)


@bot.command()
async def ban(ctx: commands.Context, member: discord.Member) -> None:
    if not await check_action('ban', ctx, member):
        return

    await ctx.guild.ban(member, reason="Забанен пользовотелями через голосование")
    await ctx.send(f"Пользователь <@{member.id}> забанен на сервере")
    logger.info(f"user {member.name}:{member.id} banned")
    user_votes.pop(member.id)


@bot.command()
async def mute(ctx: commands.Context, member: discord.Member) -> None:
    if not await check_action('mute', ctx, member):
        return

    timeout = DEFAULT_TIMEOUT_HOURS * 60

    handshake = await timeout_user(user_id=member.id, guild_id=ctx.guild.id, until=timeout)
    if handshake:
        logger.info(f"user {member.name}:{member.id} muted")
        await ctx.send("Пользователь <@{}> замьючен на {} {}".format(
            member.id, DEFAULT_TIMEOUT_HOURS,
            'час' if DEFAULT_TIMEOUT_HOURS == 1 else ('часа' if DEFAULT_TIMEOUT_HOURS < 5 else 'часов')
        ))
        user_votes.pop(member.id)

    else:
        logger.error("failed to mute user {}:{} : {}".format(
            member.name, member.id,
            handshake
        ))
        await ctx.send("Упс, что-то пошло не так")


@bot.command()
async def flush(ctx: commands.Context, member: discord.Member):
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
async def votes(ctx: commands.Context, user: discord.User):
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

    logger.debug(f"running with args: {args}")

    discord_token = os.getenv('DISCORD_TOKEN')
    logger.debug(f"got token: {discord_token}")

    if not discord_token:
        logger.error("can't find token")
        die()

    bot.run(discord_token)


if __name__ == '__main__':
    main()
