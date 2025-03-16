from loguru import logger


def setup_logger():
    logger.add("logs/pac_manager.log", rotation="1 day", retention="7 days", level="INFO")