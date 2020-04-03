/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Convenience script to quickly nop the instructions at the current selection.
// @category Memory
// @keybinding ctrl shift n
// @menupath
// @toolbar
//

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.Map.Entry;
import java.util.TreeMap;

public class NOPSelection extends GhidraScript {

    @Override
    public void run() throws Exception {

        byte[] NOPbytes = null;

        Address endAddr = null;
        Address activeAddr = null;
        Address startAddr = null;
        Address codeEnd = null;

        startAddr = activeAddr = currentSelection.getMinAddress();
        endAddr = currentSelection.getMaxAddress();

        // Create a mapping between address and instruction(s) that need to be re-disassembled after
        // the NOP replacement has taken place
        AddressSet addrSet = new AddressSet(activeAddr, endAddr);
        CodeUnitIterator iter = currentProgram.getListing().getCodeUnits(addrSet, true);

        AddressSet codeAddrSet = null;
        TreeMap<Address, AddressSet> addrToCodeMap = new TreeMap<>();

        while (iter.hasNext()) {
            activeAddr = iter.next().getAddress();

            Instruction code = getInstructionContaining(activeAddr);
            if (code != null) {
                codeEnd = activeAddr.add(code.getLength() - 1);
                codeAddrSet = new AddressSet(activeAddr, codeEnd);
                addrToCodeMap.put(activeAddr, codeAddrSet);
                continue;
            }

            if (activeAddr.equals(endAddr)) {
                break;
            }
        }

        // Removes original bytes
        clearListing(startAddr, endAddr);

        // Fill the array with the desired amount of NOPs.
        int length = (int) currentSelection.getFirstRange().getLength();
        print("NOPSelection.java> Number of bytes to be overwritten by NOPs: " + length + "\n");
        NOPbytes = new byte[length];

        for (int i = 0; i < length; i++) {
            NOPbytes[i] = (byte) 0x90;
        }

        try {
            setBytes(startAddr, NOPbytes);
        } catch (MemoryAccessException e) {
            popup("Bytes cannot be set on uninitialized memory");
            return;
        }

        // Perform dissasembly on the newly created instructions/bytes.
        for (Entry<Address, AddressSet> entry : addrToCodeMap.entrySet()) {
            DisassembleCommand cmd = new DisassembleCommand(entry.getKey(), entry.getValue(), true);
            cmd.applyTo(currentProgram, monitor);
        }
    }
}
