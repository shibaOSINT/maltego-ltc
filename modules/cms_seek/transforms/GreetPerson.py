from maltego_trx.entities import Phrase
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from modules.cms_seek.extensions import cms_seek_registry, cms_seek_set


@cms_seek_registry.register_transform(display_name="Greet Person", input_entity="maltego.Phrase",
                                   description='Returns a Phrase greeting a Person on the Graph.',
                                   output_entities=["maltego.Phrase"],
                                   transform_set=cms_seek_set)
class GreetPerson(DiscoverableTransform):

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        person_name = request.Value

        response.addEntity(Phrase, f"Hi %s, nice to meet you!".format(person_name))
