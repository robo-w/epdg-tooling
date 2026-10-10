#!/usr/bin/env python3

#
# Utility to display reduced information about a SIM card
# Based on https://gitea.osmocom.org/sim-card/pysim/src/branch/master/pySim-read.py
#
#
# Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
# Copyright (C) 2013  Alexander Chemeris <alexander.chemeris@gmail.com>
# Copyright (C) 2026  Robert Wittek
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import argparse

from pySim.legacy.ts_31_102 import EF_USIM_ADF_map
from pySim.legacy.ts_31_103 import EF_ISIM_ADF_map

from pySim.commands import SimCardCommands
from pySim.transport import init_reader, argparse_add_reader_args
from pySim.exceptions import SwMatchError
from pySim.legacy.cards import card_detect, SimCard, UsimCard, IsimCard

from pathlib import Path
import logging
from pySim.log import PySimLogger

log = PySimLogger.get(Path(__file__).stem)

option_parser = argparse.ArgumentParser(description='Legacy tool for reading some parts of a SIM card',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
argparse_add_reader_args(option_parser)


def parse_mcc_mnc(imsi: str) -> dict:
    """Parse MCC and MNC from IMSI.

    IMSI format: MCC(3 digits) + MNC(2-3 digits) + MSIN(remaining digits)
    Most commonly: MCC(3) + MNC(2) + MSIN(10) = 15 digits

    Args:
        imsi: IMSI string (typically 15 digits)

    Returns:
        Dictionary with 'mcc', 'mnc', and 'msin' keys
    """
    if not imsi or len(imsi) < 5:
        return None

    # MCC is always 3 digits
    mcc = imsi[:3]

    # MNC is typically 2 digits, but can be 3
    # Standard approach: try 2 digits first, default to 2 if ambiguous
    # Most common case is 2-digit MNC
    mnc = imsi[3:5]
    msin = imsi[5:]

    return {'mcc': mcc, 'mnc': mnc, 'msin': msin}


def select_app(adf: str, card: SimCard):
    """Select application by its AID"""
    sw = 0
    try:
        if card._scc.cla_byte == "00":
            data, sw = card.select_adf_by_aid(adf)
    except SwMatchError as e:
        if e.sw_actual == "6a82":
            # If we can't select the file because it does not exist, we just remain silent since it means
            # that this card just does not have an USIM application installed, which is not an error.
            pass
        else:
            print("ADF." + adf + ": Can't select application -- " + str(e))
    except Exception as e:
        print("ADF." + adf + ": Can't select application -- " + str(e))

    return sw


if __name__ == '__main__':

    # Parse options
    opts = option_parser.parse_args()

    # Setup logger
    PySimLogger.setup(print, {logging.WARN: "\033[33m"})

    # Init card reader driver
    sl = init_reader(opts)

    # Create command layer
    scc = SimCardCommands(transport=sl)

    # Wait for SIM card
    sl.wait_for_card(timeout=5)

    # Assuming UICC SIM
    scc.cla_byte = "00"
    scc.sel_ctrl = "0004"

    # Testing for Classic SIM or UICC
    (res, sw) = sl.send_apdu(scc.cla_byte + "a4" + scc.sel_ctrl + "02" + "3f00" + "00")
    if sw == '6e00':
        # Just a Classic SIM
        scc.cla_byte = "a0"
        scc.sel_ctrl = "0000"

    # Read the card
    print("Reading ...")

    # Initialize Card object by auto detecting the card
    card = card_detect("auto", scc) or SimCard(scc)

    # EF.IMSI
    (res, sw) = card.read_imsi()
    if sw == '9000':
        print("IMSI: %s" % (res,))
        # Parse MCC and MNC from IMSI
        imsi_parsed = parse_mcc_mnc(res)
        if imsi_parsed:
            print("  MCC: %s" % (imsi_parsed['mcc'],))
            print("  MNC: %s" % (imsi_parsed['mnc'],))
            print("  MSIN: %s" % (imsi_parsed['msin'],))
    else:
        print("Failed to read IMSI, response code = %s" % (sw,))

    # EF.SPN
    try:
        (res, sw) = card.read_spn()
        if sw == '9000':
            print("SPN: %s" % (res[0] or "Not available"))
        else:
            print("Failed to read SPN, response code = %s" % (sw,))
    except Exception as e:
        print("Failed to read SPN, response code = %s" % (str(e),))

    # EF.MSISDN
    try:
        (res, sw) = card.read_msisdn()
        if sw == '9000':
            # (npi, ton, msisdn) = res
            if res is not None:
                print("MSISDN (NPI=%d ToN=%d): %s" % res)
            else:
                print("No MSISDN available")
        else:
            print("Can't read MSISDN, response code = %s" % (sw,))
    except Exception as e:
        print("Can't read file for MSISDN -- " + str(e))

    # Check whether we have th AID of USIM, if so select it by its AID
    # EF.UST - File Id in ADF USIM : 6f38
    sw = select_app("USIM", card)
    if sw == '9000':
        # Select USIM profile
        usim_card = UsimCard(scc)

        # EF.ePDGSelection - ePDG Selection Information
        try:
            if usim_card.file_exists(EF_USIM_ADF_map['ePDGSelection']):
                (res, sw) = usim_card.read_ePDGSelection()
                if sw == '9000':
                    print("ePDGSelection:\n%s" % (res,))
                else:
                    print("Failed to read ePDGSelection, response code = %s" % (sw,))
        except Exception as e:
            print("Can't read file for ePDGSelection -- " + str(e))

    # Select ISIM application by its AID
    sw = select_app("ISIM", card)
    if sw == '9000':
        # Select USIM profile
        isim_card = IsimCard(scc)

        # EF.P-CSCF - P-CSCF Address
        try:
            if isim_card.file_exists(EF_ISIM_ADF_map['PCSCF']):
                res = isim_card.read_pcscf()
                print("P-CSCF:\n%s" %
                      (len(res) and res or '\tNot available\n',))
        except Exception as e:
            print("Can't read file for P-CSCF -- " + str(e))

        # EF.DOMAIN - Home Network Domain Name e.g. ims.mncXXX.mccXXX.3gppnetwork.org
        try:
            if isim_card.file_exists(EF_ISIM_ADF_map['DOMAIN']):
                (res, sw) = isim_card.read_domain()
                if sw == '9000':
                    print("Home Network Domain Name: %s" %
                          (len(res) and res or 'Not available',))
                else:
                    print(
                        "Failed to read Home Network Domain Name, response code = %s" % (sw,))
        except Exception as e:
            print("Can't read file for Home Network Domain Name -- " + str(e))

        # EF.IMPI - IMS private user identity
        try:
            if isim_card.file_exists(EF_ISIM_ADF_map['IMPI']):
                (res, sw) = isim_card.read_impi()
                if sw == '9000':
                    print("IMS private user identity: %s" %
                          (len(res) and res or 'Not available',))
                else:
                    print(
                        "Failed to read IMS private user identity, response code = %s" % (sw,))
        except Exception as e:
            print("Can't read file for IMS private user identity -- " + str(e))

        # EF.IMPU - IMS public user identity
        try:
            if isim_card.file_exists(EF_ISIM_ADF_map['IMPU']):
                res = isim_card.read_impu()
                print("IMS public user identity:\n%s" %
                      (len(res) and res or '\tNot available\n',))
        except Exception as e:
            print("Can't read file for IMS public user identity -- " + str(e))

    # Attempt to avoid the error on closing pcsc device on exit
    if sl:
        sl.disconnect()
        sl = None

    # Done for this card and maybe for everything ?
    print("Done !\n")
