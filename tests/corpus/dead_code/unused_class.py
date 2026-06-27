class ActiveService:
    def run(self):
        return "ok"


class LegacyService:
    def run(self):
        return "unused"


def create_service():
    return ActiveService()
