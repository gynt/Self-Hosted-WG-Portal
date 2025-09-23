import configparser
import importlib.resources
SETTINGS = configparser.ConfigParser()
SETTINGS.read_string(importlib.resources.read_text("diywgportal", "default-config.conf"))