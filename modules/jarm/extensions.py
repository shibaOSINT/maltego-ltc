from maltego_trx.decorator_registry import TransformRegistry, TransformSet

jarm_registry = TransformRegistry(
    owner="shibasec",
    author="Maltego",
    host_url="https://localhost:8080",
    seed_ids=["jarm"],
)
jarm_set = TransformSet("jarm", "jarm Transforms")
