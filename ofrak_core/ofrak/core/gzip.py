import asyncio
import logging
import tempfile
from gzip import BadGzipFile, GzipFile
from io import BytesIO
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

PIGZ = ComponentExternalTool(
    "pigz", "https://zlib.net/pigz/", "--help", apt_package="pigz", brew_package="pigz"
)


class GzipData(GenericBinary):
    """
    A gzip binary blob.
    """

    async def get_file(self) -> Resource:
        return await self.resource.get_only_child()


class GzipUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a gzip file.
    """

    id = b"GzipUnpacker"
    targets = (GzipData,)
    children = (GenericBinary,)
    external_dependencies = (PIGZ,)

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        # GzipFile is faster (spawning external processes has overhead),
        # but pigz is more willing to tolerate things like extra junk at the end
        try:
            with GzipFile(fileobj=BytesIO(data), mode="r") as gzip_file:
                return await resource.create_child(
                    tags=(GenericBinary,),
                    data=gzip_file.read(),
                )
        except BadGzipFile:
            # Create temporary file with .gz extension
            with tempfile.NamedTemporaryFile(suffix=".gz") as temp_file:
                temp_file.write(data)
                temp_file.flush()
                cmd = [
                    "pigz",
                    "-d",
                    "-c",
                    temp_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                data = stdout
                if proc.returncode:
                    # Forward any gzip warning message and continue
                    if proc.returncode == -2 or proc.returncode == 2:
                        LOGGER.warning(stderr)
                        data = stdout
                    else:
                        raise CalledProcessError(returncode=proc.returncode, cmd=cmd, stderr=stderr)

                await resource.create_child(
                    tags=(GenericBinary,),
                    data=data,
                )


class GzipPacker(Packer[None]):
    """
    Pack data into a compressed gzip file.
    """

    targets = (GzipData,)
    external_dependencies = (PIGZ,)

    async def pack(self, resource: Resource, config=None):
        gzip_view = await resource.view_as(GzipData)

        result = BytesIO()
        with GzipFile(fileobj=result, mode="w") as gzip_file:
            gzip_child_r = await gzip_view.get_file()
            gzip_data = await gzip_child_r.get_data()
            gzip_file.write(gzip_data)

        original_gzip_size = await gzip_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_gzip_size), result.getvalue())


MagicMimeIdentifier.register(GzipData, "application/gzip")
MagicDescriptionIdentifier.register(GzipData, lambda s: s.startswith("gzip compressed data"))
