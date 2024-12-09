# watcher

#### Running solution:
```
Preconditions:
 - Setup virtual env.
 - Setup env variables (openai key)

python cli.py ip4-connections-check --help
python cli.py ip4-connections-check --report_type Console
python cli.py ip4-connections-check --report_type Html
```



### The project is currently more about learning SOLID and other good practices. So, how it went?

```
1. Single Responsibility Principle (SRP):
 + in most cases classes have properly defined responsibilities 
 ? class HtmlReporter seems that break SRP, due to method 'report'
 ? in class Ip4ConnectionAnalyzer, there could be considered adding method 'prepare_sentence'

2. Open/Closed Principle (OCP):
 + systen is easy to extend, but not require modification of existing code
 + usage of abstraction (WatcherService, AnalyzerService, ReporterService) and polimorphism helps in adding new functions
 
3. Liskov Substitution Principle (LSP):
 + complianse with Liskov rule is maintained
 + interfaces are properly designed

4. Interface Segregation Principle (ISP):
 + classes imlement only what is needed
 + WatcherService, AnalyzerService i ReporterService define narrow interfaces
 + lack of not needed methods in abstractions

5. Dependency Inversion Principle (DIP):
 + Class SupervisorManager uses abstractions (AnalyzerService, ReporterService, WatcherService) instead of specific implementations (it helps with testability and extending)
 + Proper usage of compositions and dependecy from abstraction.
 ? There can be introcuded 'container DI (Dependency Injection)' to automatically manage dependencies.


6. Readibility, style of coding:
 + usage of type hints is helpful
 ? In class Ip4ConnectionAnalyzer method 'analyze_item' is too long. One can split it to smaller parts like intruduce additional 'prepare_sentence' and 'check_process' methods.


7. DRY (Don't Repeat Yourself):
 ? In class 'HtmlReporter' generating HTML could be extracted to separate method or class. Method 'report' could be smaller. Currently it is responsible for 'creating html structure', 'formating html content', 'saving file to disc'
```
