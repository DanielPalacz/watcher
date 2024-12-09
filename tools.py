from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from os import getenv

from openai import OpenAI



def configure_logger(logger_name: str) -> logging.Logger:
    """Configures logger.

    Uses env variable LOG_LEVEL_NAME:
     - CRITICAL = 50
     - FATAL = 50
     - ERROR = 40
     - WARNING = 30
     - INFO = 20
     - DEBUG = 10

    Args:
        logger_name: Logger name.

    Returns:
        Logger object.
    """
    log_level_matrix = {"CRITICAL": 50, "FATAL": 50, "ERROR": 40, "WARNING": 30, "INFO": 20, "DEBUG": 10}

    log_level_name = getenv("LOG_LEVEL_NAME") or "DEBUG"
    log_level_value = log_level_matrix[log_level_name]

    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level_value)
    logger_handler = RotatingFileHandler(f"logs/{logger_name}.log", maxBytes=100 * 1024 * 1024, backupCount=20)
    logger_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    logger_handler.setFormatter(logger_formatter)
    logger.addHandler(logger_handler)

    return logger


def ask_ai(ask: str) -> str:
    """Asks openai question.

    Args:
        ask: Question text.

    Returns:
        Answer text from the openai.
    """
    client = OpenAI(
        api_key=getenv("OPENAI_API_KEY"),
    )
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": ask,
            }
        ],
        model="gpt-4o",
    )
    return chat_completion.choices[0].message.content
