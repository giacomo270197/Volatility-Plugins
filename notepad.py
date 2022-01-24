from volatility3.framework import renderers
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements

from volatility3.plugins.windows import pslist, vadinfo


class ReadNotepad(plugins.PluginInterface):
    """Gets text off of Notepad heap"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (2, 0, 0))
            ]

    def filter_func(self, x):
        False

    def find_PID(self):
        procs = pslist.PsList.list_processes(self.context, self.config['primary'],  self.config['nt_symbols'],  filter_func = self.filter_func)
        for proc in procs:
            name = proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace')
            if name == "notepad.exe":
                return proc                           

    def detect_text(self, vad, proc):
        text_start = b"\x54\x00\x68\x00\x65\x00\x73\x00\x65\x00"
        text_end = b"\x74\x00\x2c\x00\x20\x00\x6f\x00\x75\x00\x74\x00"
        proc_layer_name = proc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        vad_content = b""
        chunk_size = 1024 * 1024 * 10
        offset = vad.get_start()
        while offset < vad.get_end():
            to_read = min(chunk_size, vad.get_end() - offset)
            vad_content += proc_layer.read(offset, to_read, pad = True)
            offset += to_read
        start_search_result = vad_content.find(text_start)
        if start_search_result != -1:
            end_search_result = vad_content.find(text_end, start_search_result)
            return [True, start_search_result, end_search_result, vad_content[start_search_result:end_search_result+1]]
        return [False, -1, -1]

    def get_VADs(self, proc):
        return vadinfo.VadInfo.list_vads(proc, filter_func = self.filter_func)

    def find_heaps(self, proc):
        heaps = []
        peb = proc.get_peb()
        number_of_heaps = peb.NumberOfHeaps
        process_heaps = peb.ProcessHeaps
        proc_layer_name = proc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        for _ in range(number_of_heaps):
            heaps.append(int.from_bytes(proc_layer.read(process_heaps, 8, pad = False), "little"))
            process_heaps += 8
        return heaps

    def _generator(self):
        proc = self.find_PID()
        heaps = self.find_heaps(proc)
        vads = self.get_VADs(proc)
        for vad in vads:
            if int(vad.get_start()) in heaps:
                res = self.detect_text(vad, proc)
                if res[0]:
                    content = res[3].replace(b"\x00", b"")
                    content = content.decode("utf-8")
                    yield (0, [content])
                    break

    def run(self):
        return renderers.TreeGrid([("Content", str)], self._generator())
