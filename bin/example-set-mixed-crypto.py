#!/usr/bin/env python

from smartpgp.highlevel import *

ctx = CardConnectionContext()

ctx.connect()
ctx.verify_admin_pin()

ctx.cmd_switch_crypto("P-521","auth")
ctx.cmd_switch_crypto("RSA","dec")
ctx.cmd_switch_crypto("brainpoolP512r1","sig")
