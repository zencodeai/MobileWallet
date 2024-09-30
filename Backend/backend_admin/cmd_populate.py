import os
import json
import dacite

from dataclasses import dataclass
from mod_utils import AdminCfg
from mod_client import RestClient


@dataclass
class DataSetData:
    # Data class for dataset
    name: str
    description: str
    icon: str


@dataclass
class DataSetEntry:
    # Dataset entry class
    data_type: str
    data: DataSetData
    record: dict | None = None


@dataclass
class DataSet:
    # Dataset class
    dataset: list[DataSetEntry]


@dataclass
class AccountData:
    # Data class for account
    name: str
    description: str
    owner_id: int
    holder_id: int


@dataclass
class FavHolderData:
    # Data class for favourite holder
    name: str
    description: str
    holder_id: int
    fav_holder_id: int


@dataclass
class FavMerchantData:
    # Data class for favourite holder
    name: str
    description: str
    holder_id: int
    fav_merchant_id: int


class CmdPopulate:
    # Status command

    def __init__(self, admin_cfg: AdminCfg, rest_client: RestClient):
        # Class constructor
        self.admin_cfg = admin_cfg
        self.rest_client = rest_client

    def _get_dataset_path(self) -> str:
        # Get dataset absolute pathname
        module_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(module_path, self.admin_cfg.dataset)

    def execute(self):
        # Execute command
        dataset_path = self._get_dataset_path()
        print(dataset_path)

        # Read dataset json
        with open(dataset_path, 'r') as f:
            dataset = json.load(f)
            dataset_obj = dacite.from_dict(data=dataset, data_class=DataSet)
            print(dataset_obj)

            # Iterate over dataset
            for e in dataset_obj.dataset:
                rsp = self.rest_client.api_put(e.data_type, e.data.__dict__)
                RestClient.assert_satus_code(rsp, [200])
                e.record = rsp.json()
                print(rsp.text)

            # Create accounts
            holders = [e for e in dataset_obj.dataset if e.data_type == 'holder']
            intermediaries = [e for e in dataset_obj.dataset if e.data_type == 'intermediary']
            for h in holders:
                for i in intermediaries:
                    account_data = AccountData(
                        name=f'{h.data.name} - {i.data.name}',
                        description=f'{h.data.name}\'s account at {i.data.description}',
                        owner_id=i.record['id'],
                        holder_id=h.record['id']
                    )
                    print(account_data)
                    rsp = self.rest_client.api_put('account', account_data.__dict__)
                    RestClient.assert_satus_code(rsp, [200])
                    print(rsp.text)

            # Create favourite holders
            for h in holders:
                fav_list = [e for e in holders if e != h]
                for f in fav_list:
                    fav_holder_data = FavHolderData(
                        name=f'{h.data.name} - {f.data.name}',
                        description=f'{h.data.name}\'s favourite {f.data.name}',
                        holder_id=h.record['id'],
                        fav_holder_id=f.record['id']
                    )
                    print(fav_holder_data)
                    rsp = self.rest_client.api_put('fav_holder', fav_holder_data.__dict__)
                    RestClient.assert_satus_code(rsp, [200])
                    print(rsp.text)

            # Create favourite merchants
            merchants_list = [e for e in dataset_obj.dataset if e.data_type == 'merchant']
            for h in holders:
                for f in merchants_list:
                    fav_merchant_data = FavMerchantData(
                        name=f'{h.data.name} - {f.data.name}',
                        description=f'{h.data.name}\'s favourite {f.data.name}',
                        holder_id=h.record['id'],
                        fav_merchant_id=f.record['id']
                    )
                    print(fav_merchant_data)
                    rsp = self.rest_client.api_put('fav_merchant', fav_merchant_data.__dict__)
                    RestClient.assert_satus_code(rsp, [200])
                    print(rsp.text)


