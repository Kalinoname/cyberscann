from abc import ABC, abstractmethod # importing module, Abstract Base Class

# creating a Base Class
class Scanner:
    def __init__(self, target: str):
        self.target = target
        self.results = {}
    
    @abstractmethod
    def scan(self):
        raise NotImplementedError("Subclasses must implement scan()")
    