from abc import ABC, abstractmethod  #

class Tool(ABC):
    @abstractmethod
    def run(self, input_data: dict) -> dict:
        """Execute the tool and return structured results"""
        pass

    @abstractmethod
    def name(self) -> str:
        """Return a unique name for the tool"""
        pass
