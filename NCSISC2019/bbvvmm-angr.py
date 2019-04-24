import angr
import logging
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY, ZERO_FILL_UNCONSTRAINED_REGISTERS, \
    UNICORN_SYM_REGS_SUPPORT, unicorn
from angr.sim_options import LAZY_SOLVES
l = logging.getLogger('test')
l.setLevel(logging.INFO)

class SkipFunc(angr.SimProcedure):
    def run(self):
        l.info('skip:%s' %self.state.regs.rip)
        return self.state.solver.BVV(0, self.state.arch.bits)

class mystrcmp(angr.SimProcedure):
    def run(self):
        l.info('skip strcmp')
        return self.state.solver.BVV(0, self.state.arch.bits)
p = angr.Project('./bbvvmm',  load_options={'auto_load_libs':False})


p.hook(0x400920, mystrcmp())
p.hook(0x4008A0, SkipFunc())
p.hook(0x400AA6, SkipFunc())
p.hook(0x405AA8, SkipFunc())
p.hook(0x4066C0, SkipFunc())
p.hook(0x401738, SkipFunc())
p.hook(0x4018C4, SkipFunc())
p.hook(0x4067BD, SkipFunc())
p.hook(0x400970, SkipFunc())

main = 0x40684A
#state = p.factory.blank_state(addr=main)
state = p.factory.blank_state(addr=main, add_options=unicorn)
#state.options.add(ZERO_FILL_UNCONSTRAINED_MEMORY)
#state.options.add(ZERO_FILL_UNCONSTRAINED_REGISTERS)
simgr = p.factory.simgr(state)

def log_state(simgr):
    l.info('active state: %d' % len(simgr.active))
    for state in simgr.active:
        l.info('rip=%s' % (state.regs.rip))
    return simgr
#simgr.explore(step_func=log_state, find=[0x406B24], avoid=[0x406B3A])
simgr.explore(find=[0x406B24], avoid=[0x406B3A])

print (len(simgr.found))

state = simgr.found[0]

print(state.posix.dumps(0))
