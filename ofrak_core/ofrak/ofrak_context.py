import asyncio
import logging
import os
import time
from types import ModuleType
from typing import Type, Any, Awaitable, Callable, List, Iterable

from synthol.injector import DependencyInjector

from ofrak.component.interface import ComponentInterface
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, FilesystemRoot
from ofrak.model.component_model import ClientComponentContext
from ofrak.model.resource_model import ResourceModel, ClientResourceContextFactory
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.id_service_i import IDServiceInterface
from ofrak.service.job_service_i import JobServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface

LOGGER = logging.getLogger("ofrak")


class OFRAKContext:
    def __init__(
        self,
        injector: DependencyInjector,
        resource_factory: ResourceFactory,
        component_locator: ComponentLocatorInterface,
        id_service: IDServiceInterface,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        job_service: JobServiceInterface,
        all_ofrak_services: List[AbstractOfrakService],
    ):
        self.injector = injector
        self.resource_factory = resource_factory
        self.component_locator = component_locator
        self.id_service = id_service
        self.data_service = data_service
        self.resource_service = resource_service
        self.job_service = job_service
        self._all_ofrak_services = all_ofrak_services
        self._resource_context_factory = ClientResourceContextFactory()

    async def create_root_resource(
        self, name: str, data: bytes, tags: Iterable[ResourceTag] = (GenericBinary,)
    ) -> Resource:
        job_id = self.id_service.generate_id()
        resource_id = self.id_service.generate_id()
        data_id = resource_id

        await self.job_service.create_job(job_id, name)
        await self.data_service.create_root(data_id, data)
        resource_model = await self.resource_service.create(
            ResourceModel.create(resource_id, data_id, tags=tags)
        )
        root_resource = await self.resource_factory.create(
            job_id,
            resource_model.id,
            self._resource_context_factory.create(),
            ResourceViewContext(),
            ClientComponentContext(),
        )
        return root_resource

    async def create_root_resource_from_file(self, file_path: str) -> Resource:
        full_file_path = os.path.abspath(file_path)
        with open(full_file_path, "rb") as f:
            root_resource = await self.create_root_resource(
                os.path.basename(full_file_path), f.read(), (File,)
            )
        root_resource.add_view(
            File(
                os.path.basename(full_file_path),
                os.lstat(full_file_path),
                FilesystemRoot._get_xattr_map(full_file_path),
            )
        )
        await root_resource.save()
        return root_resource

    async def start_context(self):
        await asyncio.gather(*(service.run() for service in self._all_ofrak_services))

    async def shutdown_context(self):
        await asyncio.gather(*(service.shutdown() for service in self._all_ofrak_services))
        logging.shutdown()


class OFRAK:
    DEFAULT_LOG_LEVEL = logging.WARNING

    def __init__(
        self,
        logging_level: int = DEFAULT_LOG_LEVEL,
        exclude_components_missing_dependencies: bool = False,
    ):
        """
        Set up the OFRAK environment that a script will use.

        :param logging_level: Logging level of OFRAK instance (logging.DEBUG, logging.WARNING, etc.)
        :param exclude_components_missing_dependencies: When initializing OFRAK, check each component's dependency and do
        not use any components missing some dependencies
        """
        logging.basicConfig(level=logging_level, format="[%(filename)15s:%(lineno)5s] %(message)s")
        logging.getLogger().addHandler(logging.FileHandler("/tmp/ofrak.log"))
        logging.getLogger().setLevel(logging_level)
        logging.captureWarnings(True)
        self.injector = DependencyInjector()
        self._discovered_modules: List[ModuleType] = []
        self._exclude_components_missing_dependencies = exclude_components_missing_dependencies

    def discover(
        self,
        module: ModuleType,
        blacklisted_interfaces: Iterable[Type] = (),
        blacklisted_modules: Iterable[Any] = (),
    ):
        self.injector.discover(module, blacklisted_interfaces, blacklisted_modules)
        self._discovered_modules.append(module)

    def set_id_service(self, service: IDServiceInterface):
        self.injector.bind_instance(service)

    async def create_ofrak_context(self) -> OFRAKContext:
        """
        Create the OFRAKContext and start all its services.
        """
        self._setup()
        component_locator = await self.injector.get_instance(ComponentLocatorInterface)

        resource_factory = await self.injector.get_instance(ResourceFactory)
        components = await self._get_discovered_components()
        component_locator.add_components(components, self._discovered_modules)

        id_service = await self.injector.get_instance(IDServiceInterface)
        data_service = await self.injector.get_instance(DataServiceInterface)
        resource_service = await self.injector.get_instance(ResourceServiceInterface)
        job_service = await self.injector.get_instance(JobServiceInterface)
        all_services = await self.injector.get_instance(List[AbstractOfrakService])

        ofrak_context = OFRAKContext(
            self.injector,
            resource_factory,
            component_locator,
            id_service,
            data_service,
            resource_service,
            job_service,
            all_services,
        )
        await ofrak_context.start_context()
        return ofrak_context

    # TODO: Typehints here do not properly accept functions with variable args
    async def run_async(self, func: Callable[["OFRAKContext", Any], Awaitable[None]], *args):
        ofrak_context = await self.create_ofrak_context()
        start = time.time()
        try:
            await func(ofrak_context, *args)
        finally:
            await ofrak_context.shutdown_context()
            print(f"It took {time.time() - start:.3f} seconds to run the OFRAK script")

    # TODO: Typehints here do not properly accept functions with variable args
    def run(self, func: Callable[["OFRAKContext", Any], Awaitable[None]], *args):
        asyncio.get_event_loop().run_until_complete(self.run_async(func, *args))

    def _setup(self):
        """Discover common OFRAK services and components."""
        import ofrak

        self.discover(ofrak)

    async def _get_discovered_components(self) -> List[ComponentInterface]:
        all_discovered_components = await self.injector.get_instance(List[ComponentInterface])
        if not self._exclude_components_missing_dependencies:
            return all_discovered_components
        LOGGER.debug(
            "`exclude_components_missing_dependencies` set True; checking each discovered component's dependencies are "
            "installed"
        )
        components_missing_deps = []
        audited_components = []
        for component in all_discovered_components:
            if all(dep.is_tool_installed() for dep in component.external_dependencies):
                audited_components.append(component)
            else:
                components_missing_deps.append(component)

        LOGGER.warning(
            f"Skipped registering the following components due to missing dependencies: "
            f"{', '.join(type(c).__name__ for c in components_missing_deps)}. Run `python3 -m "
            f"ofrak deps --missing-only` for more details."
        )

        return audited_components
