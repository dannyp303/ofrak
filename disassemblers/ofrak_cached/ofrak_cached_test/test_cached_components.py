import os
from typing import Dict
import pytest
from ofrak.core import *
from ofrak.ofrak_context import OFRAKContext
from ofrak_cached.components.cached_unpacker import (
    CachedAnalysisAnalyzer,
    CachedAnalysisAnalyzerConfig,
)
from ofrak_type import InstructionSetMode
from pytest_ofrak.patterns.code_region_unpacker import (
    CodeRegionUnpackAndVerifyPattern,
    CodeRegionUnpackerTestCase,
)
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
    ComplexBlockUnpackerTestCase,
    TEST_PATTERN_ASSETS_DIR,
)
from pytest_ofrak.patterns.basic_block_unpacker import (
    BasicBlockUnpackerUnpackAndVerifyPattern,
    BasicBlockUnpackerTestCase,
)
import ofrak_cached

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_cached)


class TestGhidraCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: CodeRegionUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(TEST_PATTERN_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource


class TestCachedComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ComplexBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(TEST_PATTERN_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource

    @pytest.fixture
    async def expected_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase) -> Dict:
        if unpack_verify_test_case.binary_md5_digest == "fc7a6b95d993f955bd92f2bef2699dd0":
            return self._fixup_test_case_for_pie(
                unpack_verify_test_case.expected_results,
                pie_base_vaddr=0x10000,
            )

        return unpack_verify_test_case.expected_results

    @pytest.fixture
    async def optional_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase):
        if unpack_verify_test_case.binary_md5_digest == "fc7a6b95d993f955bd92f2bef2699dd0":
            return set(
                self._fixup_test_case_for_pie(
                    {vaddr: [] for vaddr in unpack_verify_test_case.optional_results},
                    pie_base_vaddr=0x10000,
                ).keys()
            )

        return unpack_verify_test_case.optional_results


class TestGhidraBasicBlockUnpackAndVerify(BasicBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: BasicBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(TEST_PATTERN_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource


INSTRUCTION_MODE_TEST_CASES = [
    ("fib", "fib.json", InstructionSetMode.NONE),
    ("fib_thumb", "fib_thumb.json", InstructionSetMode.THUMB),
]


@pytest.fixture(params=INSTRUCTION_MODE_TEST_CASES, ids=lambda tc: tc[0])
async def test_case(
    pyghidra_components: None, ofrak_context: OFRAKContext, request
) -> Tuple[Resource, InstructionSetMode]:
    binary_name, cache_name, mode = request.param
    binary_path = os.path.join(ASSETS_DIR, binary_name)
    resource = await ofrak_context.create_root_resource_from_file(binary_path)
    cache_path = os.path.join(ASSETS_DIR, cache_name)
    await resource.run(
        CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=cache_path)
    )
    return resource, mode


async def test_instruction_mode(test_case: Tuple[Resource, InstructionSetMode]):
    root_resource, mode = test_case
    await root_resource.unpack_recursively()
    instructions = list(
        await root_resource.get_descendants_as_view(
            Instruction, r_filter=ResourceFilter.with_tags(Instruction)
        )
    )
    # Using "any" instead of "all" because not 100% of the basic blocks in a binary compiled with
    # "-mthumb" are in THUMB mode. This is testing (de)serialization of Ghidra analysis,
    # so all that matters is that we're seeing some instructions of the expected type
    assert any(instruction.mode == mode for instruction in instructions), (
        f"None of the instructions in {root_resource.get_id().hex()} had the expected instruction "
        f"set mode of {mode.name}."
    )