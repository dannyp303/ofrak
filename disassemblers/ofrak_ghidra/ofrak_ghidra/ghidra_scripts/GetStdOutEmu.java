import com.google.common.base.Strings;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Data;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.math.BigInteger;
import java.lang.Math;



public class GetStdOutEmu extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try{
            Emulator emu = new Emulator();
            PrintfHookHandler handler = new PrintfHookHandler(emu);
            GhidraFunction printf = new GhidraFunction(getGlobalFunctions("printf").get(0), emu);
            RetHook hook = new RetHook(printf, handler);
            emu.add_hook(hook);
            emu.run(0x13e4);
            String res = String.format("{\"result\":\"%s\"}", emu.stdOut.replaceAll("\n", "\\\\n"));
            storeHeadlessValue("OfrakResult_GetStdOutEmu", res);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }

    class Emulator extends BreakCallBack implements MemoryFaultHandler {
        long time;
        int insn_counter;
        EmulatorHelper emu;
        Memory mem;
        Heap heap;
        List<RetHook> hooks = new ArrayList<RetHook>(); 
        List<Address> run_until;
        
        String stdOut = new String();

        Emulator() {
            this.resetMemState();
        }

        void add_hook(RetHook hook){
            this.hooks.add(hook);
        }

        boolean is_running(){
            return (this.run_until.size() > 0);
        }

        long get_reg(Register reg){
            return this.emu.readRegister(reg).longValue();
        }

        long get_pc(){
            return this.get_reg(this.emu.getPCRegister());
        }

        long get_sp(){
            return this.get_reg(this.emu.getStackPointerRegister());
        }

        long get_ra() throws Exception{
            return this.get_stack_val(0, 4);
        }

        long get_stack_val(int offset, int size) throws Exception{
            try{
                long val = this.emu.readStackValue(offset, size, false).longValue();
                if (val < 0) {
                    long mask = (1 << (size * 8)) - 1;
                    val = ((val * -1) ^ mask) + 1;
                }
                return val;
            } catch(Exception e) {
                e.printStackTrace();
                throw e;
            }
        }
        
        long get_var(Variable var) throws Exception{
            long val;

            if(var.isRegisterVariable()) {
                val = this.get_reg(var.getRegister());
            } else if(var.isStackVariable()) {
                val = this.get_stack_val(var.getStackOffset(), var.getLength());
            } else {
                throw new Exception();
            }
            return val;
        }

        void set_var(Variable var, long val) throws Exception{
            if (var.isRegisterVariable()) {
                this.set_reg(var.getRegister(), val);
            }
            else if (var.isStackVariable()){
                this.emu.writeStackValue(var.getStackOffset(), var.getLength(), val);
            }
            else {
                throw new Exception("Bad Variable Type");
            }
        }

        void set_reg(Register reg, long val){
            this.emu.writeRegister(reg, val);
        }

        void set_pc(long pc_val){
            this.set_reg(this.emu.getPCRegister(), pc_val);
        }

        void set_sp(long sp_val){
            this.set_reg(this.emu.getStackPointerRegister(), sp_val);
        }

        String read_str(Address addr, int maxlen) throws Exception{
            Data data = getDataAt(addr);
            if(!data.hasStringValue()) {
                try{
                    createAsciiString(addr);
                } catch(Exception e){
                    throw new Exception("Not a string");
                }
            } 
            return (String) data.getValue();
        }

        public void run(long final_pc) throws Exception {
            RegisterValue ctx_val;
            Function fn = getGlobalFunctions("main").get(0);
            this.set_sp(0xf0000000);
            this.set_pc(fn.getEntryPoint().getOffset());
            Address pc = toAddr(this.get_pc());
            Address prev_pc;

            while (!(pc.getOffset() == final_pc)) {
                ctx_val = currentProgram.getProgramContext().getDisassemblyContext(pc);
                this.emu.setContextRegister​(ctx_val);
                prev_pc = pc;
                this.emu.step(TaskMonitor.DUMMY);
                pc = toAddr(this.get_pc());
                for(RetHook hook: this.hooks){
                    if (pc.equals(hook.func.fn.getEntryPoint())){
                        hook.call();
                    }
                }

                if (fn.getReturn().equals(null)){
                    return;
                };
            }
        }

        public String get_string(Variable var) throws Exception{
            if ((var != null) && !(var.getDataType() instanceof VoidDataType)) {
                long val;
                try{
                    val = this.get_var(var);
                } catch(Exception e) {
                    println(e.toString());
                    throw e;
                }
                if(var.getDataType() instanceof Pointer) {
                    Pointer pointer = (Pointer)var.getDataType();
                    if(pointer.getDataType() instanceof CharDataType) {
                        return this.read_str(toAddr(val), 1000);
                    } else {
                        return String.valueOf(val);
                    }
                } else {
                    throw new Exception("Not a pointer");
                }
            }
            throw new Exception("Bad Var");
        }

        public boolean uninitializedRead​(Address address, int size, byte[] buf, int bufOffset){
            return true;
        }

        public boolean unknownAddress(Address address, boolean write){
            return true;
        }

        void resetMemState() {
            this.time = System.currentTimeMillis();
            this.insn_counter = 0;
            this.emu = new EmulatorHelper(currentProgram);
            this.mem = new Memory(this.emu);
            this.emu.registerDefaultCallOtherCallback(this);
            // this.emu.emulator.addMemoryAccessFilter(this.mem);
            this.emu.enableMemoryWriteTracking(true);
            this.heap = new Heap(0x80000000);
        }
    }

    class GhidraFunction {
        Function fn;
        Emulator emu;

        GhidraFunction(Function fn, Emulator emu){
            this.fn = fn;
            this.emu = emu;
        }

        void do_return() throws Exception{
            emu.set_pc(emu.get_ra());
        }

        void call(Long[] args) throws Exception {
            if (!this.emu.is_running()){
                this.emu.set_sp(0xf0000000);
            }
            int stack_sub = 0;
            Parameter[] parameters = this.fn.getParameters();
            for(Parameter param: parameters) {
                if (param.isStackVariable()){
                    stack_sub = (int)Math.max(stack_sub, param.getStackOffset());
                }
            }
            this.emu.set_sp(this.emu.get_sp() - stack_sub);
            this.emu.set_pc(this.fn.getEntryPoint().getOffset());
            if (args.length != parameters.length){
                throw new Exception("Incorrect number of arguments");
            }
            for(int i = 0; i < args.length; i++){
                this.emu.set_var(parameters[i], args[i]);
            }
            this.do_return();
        }
    }

    class HookHandler {
        Emulator emu;
        HookHandler(Emulator emu){
            this.emu = emu;
        }
        public void call(Parameter[] params) throws Exception{
            return;
        }
    }

    class RetHook {
        HookHandler handler;
        GhidraFunction func;
        Parameter[] params;
        Parameter ret;
        
        RetHook(GhidraFunction func, HookHandler handler) {
            this.handler = handler;
            this.func = func;
            this.params = func.fn.getParameters();
            this.ret = func.fn.getReturn();
        }
        
        public void call() throws Exception{
            this.handler.call(this.params);
            this.func.do_return();
        }
    }

    class PrintfHookHandler extends HookHandler{
        Emulator emu;
        PrintfHookHandler(Emulator emu){
            super(emu);
            this.emu = emu;
        }

        @Override
        public void call(Parameter[] params) throws Exception{
            String fmt = emu.get_string(params[0]);
            long arg2 = emu.get_stack_val(8, 4);
            emu.stdOut += String.format(fmt, arg2);
        }
    }
    class Memory extends MemoryAccessFilter{
        EmulatorHelper emu;

        Memory(EmulatorHelper emu) {
            super();
            this.emu = emu;
            this.setFilterOnExecutionOnly(false);
        }

        public void processRead​(AddressSpace spc, long off, int size, byte[] values){
            return;
        }

        public void processWrite​(AddressSpace spc, long off, int size, byte[] values){
            return;
        }
    }

    class Heap {
        int addr;

        Heap(int addr){
            this.addr = addr;
        }
    }
}
