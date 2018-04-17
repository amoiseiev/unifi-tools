#!/usr/bin/python

import json
import logging
import subprocess
import sys

from logging.handlers import RotatingFileHandler
from logging import StreamHandler

VYATTA_OP_CMD = '/opt/vyatta/bin/vyatta-op-cmd-wrapper'
PRIMARY_GW_METRIC = "1"
SECONDARY_GW_METRIC = "230"

logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s')

stdout_handler = StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

try:
    file_handler = RotatingFileHandler('/var/log/usg-failover-nanny.log', maxBytes=2000, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except:
    logger.error("Cannot setup file logger. Exiting")
    sys.exit(2)

logger.setLevel(logging.DEBUG)


def lb_status_to_json(lb_status_output):
    lb_status_array = lb_status_output.splitlines()

    lb_status_dict = {}
    cur_group = ''
    cur_interface = ''

    validation_cnt_dict = {
        'interface': 0,
        'group': 0,
        'failover': 0,
        'active': 0
    }
    required_properties = [
        'carrier',
        'status',
        'gateway',
        'route table',
        'weight',
        'flows'
    ]

    for element in lb_status_array:
        el_level = len(element) - len(element.lstrip())

        if el_level == 0 and element:
            validation_cnt_dict['group'] += 1
            cur_group = element.strip()
            lb_status_dict[cur_group] = {}
        elif el_level == 2:
            property = element.split(':')
            if len(property) == 2 and property[0].strip() == "interface":
                validation_cnt_dict['interface'] += 1
                cur_interface = property[1].strip()
                lb_status_dict[cur_group].update({cur_interface: {}})
            elif len(property) == 2 and cur_interface:
                lb_status_dict[cur_group][cur_interface].update(
                    {property[0].strip(): property[1].strip()}
                )
                if (
                    property[0].strip() == 'status' and
                    property[1].strip() == 'active'
                ):
                    validation_cnt_dict['active'] += 1
                elif (
                    property[0].strip() == 'status' and
                    property[1].strip() == 'failover'
                ):
                    validation_cnt_dict['failover'] += 1
            elif len(property) == 1 and property[0].strip() == "flows":
                lb_status_dict[cur_group][cur_interface].update(
                    {property[0].strip(): {}}
                )
        elif el_level in [4, 6] and cur_group and cur_interface:
            property = element.split(':')
            if len(property) == 2:
                lb_status_dict[cur_group][cur_interface]['flows'].update(
                    {property[0].strip(): property[1].strip()}
                )

    if (
        validation_cnt_dict['group'] == 1 and
        validation_cnt_dict['interface'] == 2 and
        validation_cnt_dict['failover'] == 1 and
        validation_cnt_dict['active'] == 1
    ):

        for i in lb_status_dict[cur_group].keys():
            for j in required_properties:
                if j not in lb_status_dict[cur_group][i]:
                    return {}

        return lb_status_dict
    else:
        return {}


def get_lb_status():
    lb_status = subprocess.Popen(
        [VYATTA_OP_CMD, 'show', 'load-balance', 'status'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    lb_status_output, lb_status_error = lb_status.communicate()

    if not lb_status_error:
        return lb_status_output
    else:
        return {}


def get_routes_json():
    routes = subprocess.Popen(
        [VYATTA_OP_CMD, 'show', 'ip', 'route', 'json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    routes_output, routes_error = routes.communicate()

    if not routes_error:
        return json.loads(routes_output)
    else:
        logger.debug(routes_error)
        return {}


def set_gw_metric(gw_route):

    logger.debug(gw_route)

    c = subprocess.Popen(
        [
            "/usr/bin/vtysh", "-c",
            "conf t", "-c",
            "ip route 0.0.0.0/0 {0} {1}".format(
                gw_route["gateway"], gw_route["metric"]
                )
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    c_output, c_error = c.communicate()

    logger.debug(c_output)

    if c_error:
        logger.error(c_error)
        return False
    else:
        return True


def main():
    logger.info("Getting load balancing status")

    lb_status = lb_status_to_json(get_lb_status())
    logger.debug(lb_status)

    logger.info("Getting active routes")
    routes = get_routes_json()
    logger.debug(routes)

    if lb_status and routes:
        logger.info("Successfully got load balancing status and active routes")
    else:
        logger.error("Cannot get load balancing status or routes. Exiting")
        sys.exit(1)

    ds_dict = {}

    for group in lb_status:
        logger.debug(group)
        for interface in lb_status[group]:
            logger.debug("checking interface {0}".format(interface))
            interface_details = lb_status[group][interface]
            logger.debug("Interface details: {0}".format(interface_details))

            ds_dict[interface] = {
                "gateway": interface_details["gateway"]
            }

            if interface_details["carrier"] == "up":
                logger.debug("Carrier is up")
                ds_dict[interface].update(
                    {
                        "metric": PRIMARY_GW_METRIC if
                        interface_details["status"] == "active"
                        else SECONDARY_GW_METRIC
                    }
                )

    logger.info("Desired state: {0}".format(ds_dict))
    logger.info("Validating routes")

    for route in routes:
        if (
            "pfx" in route and
            "nh" in route and
            route["pfx"] == "0.0.0.0/0"
        ):
            logger.info("Found default route: {0}".format(route))

            for route_details in route["nh"]:
                if (
                    "via" not in route_details or
                    "intf" not in route_details
                ):
                    continue

                logger.info("Checking default route and its priority")
                cur_interface = route_details["intf"]
                if "metric" in route_details:
                    cur_metric = route_details["metric"].split("/")[0]
                else:
                    cur_metric = ""

                if (
                    route_details["via"] == ds_dict[cur_interface]["gateway"]
                ):
                    logger.info("default route and gw match for {0}".format(cur_interface))
                    if cur_metric == ds_dict[cur_interface]["metric"]:
                        logger.info("{0} gateway metric is correct".format(cur_interface))
                    else:
                        logger.info("{0} metric is not in route details or incorrect, resetting".format(cur_interface))
                        set_gw_metric(ds_dict[cur_interface])

    exit(0)


main()
