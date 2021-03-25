#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : Scan devices demo
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
    i = 0
    displayed = 0
    while True:
        try:
            current_card = OpenPGPpy.OpenPGPcard(reader_index=i)
            print("--------------------------------------------------------")
            print(f"OpenPGP card/reader : {current_card.name}")
            print(f"OpenPGP version     : {current_card.pgpverstr}")
            print(
                f"Manufacturer        : {current_card.manufacturer} ({current_card.manufacturer_id})"
            )
            print(
                f"Device serial       : {current_card.serial}  ({hex(current_card.serial)})"
            )
            displayed += 1
            i += 1
        except OpenPGPpy.ConnectionException as exc:
            if str(exc) != "No OpenPGP applet on this reader.":
                break
            i += 1
    if displayed == 0:
        print("No OpenPGP device available")


if __name__ == "__main__":
    main()
