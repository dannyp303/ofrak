import configparser
import math
import os
import platform
from multiprocessing import Pool, cpu_count
from typing import Optional, Dict, Mapping, Tuple

from ofrak_patch_maker.toolchain.model import BinFileType, Segment
from ofrak_type.error import NotFoundError
from ofrak_type.memory_permissions import MemoryPermissions


def get_file_format(path):
    try:
        import magic
    except ImportError:
        # ImportError is likely raise because libmagic cannot be found on the system. See error message.
        raise

    result = magic.from_file(path).split(" ")[0].lower()
    try:
        return BinFileType(result)
    except:
        ValueError("Invalid BinFileType!!!")


def get_repository_config(section: str, key: Optional[str] = None):
    """
    Find config file and values. Look in user's `~/etc` directory followed by `/etc`.

    :param section: section name in config file
    :param key: key in `config[section]`

    :raises SystemExit: If `config[section]` or `config[section][key]` not found.
    :raises KeyError: If the `$HOME` environment variable is not found.
    :return Union[str, List[Tuple[str, str]]]: the result of ``config.get(section, key)`` or
        ``config.items(section)``
    """

    config = configparser.RawConfigParser()
    config_name = "toolchain.conf"
    if platform.system().find("CYGWIN") > -1 or platform.system().find("Windows") > -1:
        config_root = "/winetc"
    else:
        config_root = "/etc"
    local_config = os.path.join(os.path.dirname(__file__), os.path.pardir)
    config_paths = [config_root, local_config]
    try:
        local_etc = os.path.join(os.environ["HOME"], "etc")
        config_paths = [local_etc] + config_paths
    except KeyError:
        print("unable to find home directory")

    error_by_config_file: Dict[str, Exception] = dict()
    for p in config_paths:
        conf = os.path.join(p, config_name)
        if not os.path.exists(conf):
            continue
        try:
            config.read(conf)
            if key:
                ret = config.get(section, key)
            else:
                ret = config.items(section)  # type: ignore
            return ret
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            error_by_config_file[conf] = e
            continue

    if 0 == len(error_by_config_file):
        raise NotFoundError(f"Configuration file {config_name} not found")

    elif 1 == len(error_by_config_file):
        _config, _e = next(iter(error_by_config_file.items()))
        raise NotFoundError(f"Section or option not found in {_config}", _e)

    else:
        raise NotFoundError(
            f"Section {section:s} or option {key:s} not found in any of the configs searched: "
            f"{error_by_config_file}"
        )


# TODO: Add a main driver for this guy
NULL_DATA = Segment(
    segment_name=".data",
    vm_address=0,
    offset=0,
    is_entry=False,
    length=0,
    access_perms=MemoryPermissions.RW,
)


def generate_arm_stubs(
    func_names: Mapping[str, int], out_dir: str, thumb: bool = False
) -> Mapping[str, Tuple[Segment, Segment]]:
    """
    Utility function to generate assembly stubs. This is necessary when function calls need to
    switch between ARM and thumb mode (when code generated by the PatchMaker is ARM and needs to
    jump to thumb code, or the opposite). With those stubs, the linker has explicit information
    about the destination mode, so it jumps correctly (exchanging mode or not).

    It is not [PatchMaker][ofrak_patch_maker.patch_maker.PatchMaker]'s responsibility to
    programmatically generate source in this way.

    Furthermore, this functionality is much more complex than `base_symbols={}` addition implies,
    as actual object files are generated and linked against.

    :param func_names: names to effective address
    :param out_dir: object file output directory
    :param thumb: Whether or not to generate thumb stubs

    :return Dict[str, Tuple[Segment, Segment]: maps object file to dummy
    `[text_segment, data segment]`
    """
    print(f"Generating ARM stubs...")
    names = list(func_names.keys())
    addresses = list(func_names.values())
    out_dirs = [out_dir] * len(names)
    if thumb:
        stub_strs = [".thumb_func"] * len(names)
    else:
        stub_strs = [f".type {name}, %function" for name in names]
    args = zip(names, addresses, stub_strs, out_dirs)
    workers = math.ceil(0.6 * cpu_count())
    with Pool(processes=workers) as pool:
        result = pool.starmap(_gen_file, args, chunksize=math.ceil(len(names) / workers))
    segment_map: Dict[str, Tuple[Segment, Segment]] = {}
    for r in result:
        segment_map.update(r)
        print(list(r.keys()))
    return segment_map


# Helper function excluded from function coverage results since it runs in a process pool. Tests
# for generate_arm_stubs test this helper function.
def _gen_file(  # pragma: no cover
    name: str, address: int, stub_str: str, out_dir: str
) -> Mapping[str, Tuple[Segment, Segment]]:
    path = os.path.join(out_dir, name + ".as")
    with open(path, "w") as f:
        f.write(f"{stub_str}\n.global {name}\n{name}:\n")
    segment = Segment(
        segment_name=".text",
        vm_address=address,
        offset=0,
        is_entry=False,
        length=0,
        access_perms=MemoryPermissions.RX,
    )
    return {path: (segment, NULL_DATA)}
