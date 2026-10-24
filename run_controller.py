#!/usr/bin/python3
import logging
from os_ken.base import app_manager
from os_ken.lib import hub

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

def main():
    manager = app_manager.AppManager.get_instance()
    manager.load_apps(["sdn_controller"])
    contexts = manager.create_contexts()
    services = manager.instantiate_apps(**contexts)
    try:
        hub.joinall(services)
    finally:
        manager.close()

if __name__ == "__main__":
    main()
