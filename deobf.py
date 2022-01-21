from ida_hexrays import *
import ida_idaapi


class subinsn_optimizer_t(minsn_visitor_t):
    def __init__(self):
        minsn_visitor_t.__init__(self)
    def visit_minsn(self):      
        minsn = self.curins       
        if minsn.opcode == m_mov and minsn.l != 0 and not minsn.l.is_reg() and minsn.l.dstr().find("$q") == 0:
            if not minsn.l.has_side_effects():
                print(minsn.l.dstr())
                minsn.l.make_number(0, 4)
        return 0


class sample_optimizer_t(optinsn_t):
    def __init__(self):
        optinsn_t.__init__(self)
    def func(self, blk, ins, optflags):
        opt = subinsn_optimizer_t()
        ins.for_all_insns(opt)      
        return 0


class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Microcode deobfuscation"
    wanted_hotkey = ""
    comment = "A simple plugin to deobfuscate null indexes in arrays by q* signature"
    help = ""
    def init(self):
        if init_hexrays_plugin():
            self.optimizer = sample_optimizer_t()
            self.optimizer.install()
            return ida_idaapi.PLUGIN_KEEP 
    def term(self):
            self.optimizer.remove()
    def run(self):
            pass

def PLUGIN_ENTRY():
    return my_plugin_t()
