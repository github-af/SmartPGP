#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : Reset device demo
# Copyright (C) 2020  BitLogiK
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import getpass


try:
    import OpenPGPpy
except ModuleNotFoundError:
    # Import the OpenPGPpy from parent or current folder
    # Can run demo w/o OpenPGPpy installed (from root or demo folder)
    from sys import path

    path.append(".")
    path.append("..")
    import OpenPGPpy


def main():
    mydevice = OpenPGPpy.OpenPGPcard()
    print("Enter the PUK to reset the", mydevice.name)
    PIN3 = "12345678" #getpass.getpass("Enter PIN3 (PUK) : ")
    try:
        mydevice.reset(PIN3)
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw_code == 0x6982 or exc.sw_code == 0x6A80:
            print("Error: Wrong PUK")
        return
    print("Reset done.")


if __name__ == "__main__":
    main()
