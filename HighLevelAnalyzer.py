# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# for LR11xx --- https://www.semtech.com/products/wireless-rf/lora-edge/lr1110

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import ctypes
from enum import Enum
c_uint8 = ctypes.c_uint8
c_uint32 = ctypes.c_uint32

RADIO_SET_RX         = 0x0209
RADIO_SET_TX         = 0x020a
RADIO_SET_STANDBY    = 0x011c
RADIO_SET_SLEEP      = 0x011b
RADIO_SETDIOIRQPARAMS = 0x0113
RADIO_GNSS_SCAN     = 0x040b
RADIO_WIFI_SCAN     = 0x0301

class RadioOpMode(Enum):
    NONE = 0,
    SLEEP = 1,
    WAKEUP = 2,
    STANDBY_RC = 3,
    STANDBY_XOSC = 4,
    FS = 5
    RX = 6,
    TX = 7,
    SNIFF = 8   # wifi or GNSS

#class PacketType(Enum):
#    NONE = 0 
#    LORA = 1,
#    FSK = 2,
#    FHSS = 3

class Stat1_bits( ctypes.LittleEndianStructure ):
    _fields_ = [
                ("intActive",      c_uint8, 1 ),  # 
                ("cmdStatus", c_uint8, 3 ),  # 
                ("RFU",      c_uint8, 4 ),  # 
               ]

class Stat1( ctypes.Union ):
     _anonymous_ = ("bit",)
     _fields_ = [
                 ("bit",    Stat1_bits ),
                 ("asByte", c_uint8    )
                ]

class Stat2_bits( ctypes.LittleEndianStructure ):
    _fields_ = [
                ("bootLoader",  c_uint8, 1 ),  # 
                ("chipMode",    c_uint8, 3 ),  # 
                ("resetStatus", c_uint8, 4 ),  # 
               ]

class Stat2( ctypes.Union ):
     _anonymous_ = ("bit",)
     _fields_ = [
                 ("bit",    Stat2_bits ),
                 ("asByte", c_uint8    )
                ]

class SleepConfig_bits( ctypes.LittleEndianStructure ):
    _fields_ = [
                ("retention", c_uint8, 1 ),  #
                ("wakeup",    c_uint8, 1 ),  #
                ("RFU",       c_uint8, 6 ),  #
               ]

class SleepConfig( ctypes.Union ):
     _anonymous_ = ("bit",)
     _fields_ = [
                 ("bit",    SleepConfig_bits ),
                 ("asByte", c_uint8    )
                ]

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    cmdDict = {
        RADIO_SET_RX: "setRx",
        RADIO_SET_TX: "setTx",
        RADIO_SET_STANDBY: "setStandby",
        RADIO_SET_SLEEP: "setSleep",
        RADIO_SETDIOIRQPARAMS: "setDioIrqParams",
        RADIO_GNSS_SCAN: "GnssScan",
        RADIO_WIFI_SCAN: "WifiScanTimeLimit",
    }

    def parseStatus_to_af(self, arg, frame: AnalyzerFrame, cmd):
        stat1 = Stat1()
        stat1.asByte = self.ba_miso[0]
        if stat1.cmdStatus == 3:
            # nothing useful for opMode on CMD_DAT from device
            return None

        my_ret = None
        stat2 = Stat2()
        stat2.asByte = self.ba_miso[1]

        # the radio changed mode by itself
        if self.mode == RadioOpMode.FS and stat2.chipMode != 3:
            dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
            dur_ms_str = f"{dur_ms:.5f}" + "ms"
            my_ret = AnalyzerFrame('fsEnd', self.mode_start_at, self.nss_fall_time, {'string':"FS " + dur_ms_str})
            self.mode_start_at = self.nss_fall_time

        if self.mode == RadioOpMode.RX and stat2.chipMode != 4:
            dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
            dur_ms_str = f"{dur_ms:.5f}" + "ms"
            my_ret = AnalyzerFrame('rxEnd', self.mode_start_at, self.nss_fall_time, {'string':"RX " + dur_ms_str})
            self.mode_start_at = self.nss_fall_time

        if self.mode == RadioOpMode.TX and stat2.chipMode != 5:
            dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
            dur_ms_str = f"{dur_ms:.5f}" + "ms"
            my_ret = AnalyzerFrame('txEnd', self.mode_start_at, self.nss_fall_time, {'string':"TX " + dur_ms_str})
            self.mode_start_at = self.nss_fall_time

        if self.mode == RadioOpMode.STANDBY_XOSC and stat2.chipMode != 2:
            # CalibImage will put radio into StbyRc
            dur_ms = float(self.nss_fall_time- self.mode_start_at) * 1000
            dur_ms_str = f"{dur_ms:.5f}" + "ms"
            my_ret = AnalyzerFrame('stbyXosc', self.mode_start_at, self.nss_fall_time, {'string':"STBY_XOSC " + dur_ms_str})
            self.mode_start_at = self.nss_fall_time

        if self.mode == RadioOpMode.SNIFF and stat2.chipMode != 6:
            dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
            dur_ms_str = f"{dur_ms:.5f}" + "ms"
            my_ret = AnalyzerFrame('sniffEnd', self.mode_start_at, self.nss_fall_time, {'string':"SNIFF " + dur_ms_str})
            self.mode_start_at = self.nss_fall_time

        #if self.mode == RadioOpMode.STANDBY_RC and stat2.chipMode != 1:  # is this happening?
        commanded_mode = RadioOpMode.NONE

        if cmd == RADIO_SET_RX:
            commanded_mode = RadioOpMode.RX
        elif cmd == RADIO_SET_TX:
            commanded_mode  = RadioOpMode.TX
        elif cmd == RADIO_SET_STANDBY:
            cfg = self.ba_mosi[2]
            if cfg == 0:
                commanded_mode = RadioOpMode.STANDBY_RC
            elif cfg == 1:
                commanded_mode = RadioOpMode.STANDBY_XOSC
            else:
                print('SetStandby ? ' + hex(cfg) + ' ?')
        elif cmd == RADIO_SET_SLEEP:
            commanded_mode = RadioOpMode.SLEEP
            self.sleep_cfg.asByte = self.ba_mosi[2]
        elif cmd == RADIO_GNSS_SCAN or cmd == RADIO_WIFI_SCAN:
            commanded_mode = RadioOpMode.SNIFF

        if commanded_mode != RadioOpMode.NONE:  # host send opcode which changes radio operating mode
            cmd_str = self.cmdDict[cmd]
            if self.mode == RadioOpMode.STANDBY_XOSC:
                dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('stbyXosc', self.mode_start_at, frame.end_time, {'string':"STBY_XOSC " + dur_ms_str + " cmd="+cmd_str})
            elif self.mode == RadioOpMode.STANDBY_RC:
                dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('stbyRc', self.mode_start_at, frame.end_time, {'string':"STBY_RC " + dur_ms_str + " cmd="+cmd_str})
            elif self.mode == RadioOpMode.FS:
                dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('fs', self.mode_start_at, frame.end_time, {'string':"FS " + dur_ms_str + " cmd="+cmd_str})
            elif self.mode == RadioOpMode.RX:
                dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('rxEnd', self.mode_start_at, frame.end_time, {'string':"RX " + dur_ms_str + " cmd=" + cmd_str})
            elif self.mode == RadioOpMode.WAKEUP:
                dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('wakeB', self.mode_start_at, frame.end_time, {'string':"___ cmd-stdby-wake ___" + dur_ms_str})
            else:
                print("TODO SET_RX/TX at mode " + str(self.mode) + " " + str(self.foobar))
            self.mode = commanded_mode
            self.mode_start_at = frame.end_time
            return my_ret

        if self.mode == RadioOpMode.STANDBY_RC and stat2.chipMode != 1:
            if self.mode_start_at != 0:
                dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                dur = self.nss_fall_time - self.mode_start_at
                my_ret = AnalyzerFrame('stbyRc', self.mode_start_at, self.nss_fall_time, {'string':"STBY_RC " + dur_ms_str})
                self.mode_start_at = self.nss_fall_time
            else:
                print("leaving stdbyRc but zero mode_start_at")

        if self.mode == RadioOpMode.STANDBY_XOSC and stat2.chipMode != 2:
            self.mode_start_at = self.nss_fall_time

        if self.mode == RadioOpMode.NONE:
            print("mode NONE set start")
            self.mode_start_at = self.nss_fall_time

        if stat2.chipMode == 0:
            self.mode = RadioOpMode.SLEEP # ? how would this ever happen ?
        elif stat2.chipMode == 1:
            self.mode = RadioOpMode.STANDBY_RC
        elif stat2.chipMode == 2:
            self.mode = RadioOpMode.STANDBY_XOSC
        elif stat2.chipMode == 3:
            self.mode = RadioOpMode.FS
        elif stat2.chipMode == 4:
            self.mode = RadioOpMode.RX
        elif stat2.chipMode == 5:
            self.mode = RadioOpMode.TX
        elif stat2.chipMode == 6:
            self.mode = RadioOpMode.SNIFF
        else:
            print('chipmode ?' + str(stat2.chipMode) + '?')

        return my_ret

    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        },
        'match': { 'format': '{{data.string}}'},
        'wakeA': { 'format': '{{data.string}}'},
        'wakeB': { 'format': '{{data.string}}'},
        'sleepEnd': { 'format': '{{data.string}}'},
        'stbyRc': { 'format': '{{data.string}}'},
        'stbyXosc': { 'format': '{{data.string}}'},
        'fs': { 'format': '{{data.string}}'},
        'fsEnd': { 'format': '{{data.string}}'},
        'rxEnd': { 'format': '{{data.string}}'},
        'txEnd': { 'format': '{{data.string}}'},
        'sniffEnd': { 'format': '{{data.string}}'}
    }

    def __init__(self):
        self.mode_start_at = 0
        self.idx = 0
        self.cmd_direct_read = 0
        self.next_transfer_response = 0
        self.mode = RadioOpMode.NONE
        self.foobar = 0
        self.sleep_cfg = SleepConfig()

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'result':
            if self.idx == 0:
                self.ba_mosi = frame.data['mosi']
                self.ba_miso = frame.data['miso']
            else:
                self.ba_mosi += frame.data['mosi']
                self.ba_miso += frame.data['miso']
            self.idx += 1
        elif frame.type == 'enable':   # falling edge of nSS
            my_ret = None
            if self.mode == RadioOpMode.WAKEUP:
                dur_ms = float(frame.start_time - self.mode_start_at) * 1000
                dur_ms_str = f"{dur_ms:.5f}" + "ms"
                my_ret = AnalyzerFrame('wakeA', self.mode_start_at, frame.start_time, {'string':"wakeup " + dur_ms_str})
                self.mode_start_at = frame.start_time

            self.ba_mosi = b''
            self.ba_miso = b''
            self.nss_fall_time = frame.start_time
            self.idx = 0
            return my_ret
        elif frame.type == 'disable':   # rising edge of nSS
            self.foobar = self.foobar + 1
            self.idx = -1

            if len(self.ba_mosi) > 0:
                if self.cmd_direct_read == 0:
                    cmd = int.from_bytes(bytearray(self.ba_mosi[0:2]), 'big')
                else:
                    cmd = 0

                my_ret = None
                if len(self.ba_mosi) > 2:
                    my_ret = self.parseStatus_to_af(self.ba_miso[1], frame, cmd)
                elif self.mode == RadioOpMode.WAKEUP:
                    dur_ms = float(frame.end_time - self.mode_start_at) * 1000
                    dur_ms_str = f"{dur_ms:.5f}" + "ms"
                    my_ret = AnalyzerFrame('ndWake', self.mode_start_at, frame.end_time, {'string':"wake " + dur_ms_str})
                    self.mode_start_at = frame.end_time # save starting point for next mode

                return my_ret
            else:
                if self.mode == RadioOpMode.SLEEP:
                    dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
                    dur_ms_str = f"{dur_ms:.5f}" + "ms"
                    sleep_str = ""
                    if self.sleep_cfg.retention == 1:
                        sleep_str = sleep_str + 'retention '
                    if self.sleep_cfg.wakeup == 1:
                        sleep_str = sleep_str + 'rtc-wakeup '
                    my_ret = AnalyzerFrame('sleepEnd', self.mode_start_at, self.nss_fall_time, {'string':"SLEEP " + sleep_str + dur_ms_str})
                elif self.mode == RadioOpMode.STANDBY_XOSC:
                    # did the host think device was asleep?  (hint, it wasnt)
                    print("wake from STANDBY_XOSC")
                    dur_ms = float(self.nss_fall_time - self.mode_start_at) * 1000
                    dur_ms_str = f"{dur_ms:.5f}" + "ms"
                    my_ret = AnalyzerFrame('stbyXosc', self.mode_start_at, self.nss_fall_time, {'string':"STBY_XOSC " + dur_ms_str})
                else:
                    my_ret = None
                    print("wake start not in sleep --> " + str(self.mode))
                self.mode = RadioOpMode.WAKEUP 
                self.mode_start_at = self.nss_fall_time
                return my_ret
        elif frame.type == 'error':
            print('error');

