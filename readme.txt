--- RU ---
Эта библиотека может помочь в изучении PE формата (PE - Portable Executable - *.exe;*.dll;...).
Библиотека содержит свой набор структур описания формата, но ни что не мешает, получив одну структуру, привести ее к структуре из заголовка WinNT.h. Это легко делается.
А свои структуры я завел исключительно ради полного изучения всех полей DOS-, PE- и COFF- заголовков. К тому же мне немного легче работать с кроссплатформенными типами данных, хотя этот фактор был менее всего значим.
Первый раз такую библиотеку я писал еще в 2007 году, этот вариант - это уже переработка с учетом некоторых моих текущих знаний.

Задуматься над такой библиотекой меня сподвигла статья : http://www.rsdn.ru/?article/baseserv/peloader.xml
А источники, которые я изучал для написания, и вспомнить уже не удастся, их было очень много.

Это уже готовая библиотека, которую вполне можно использовать для работы с небольшим dll-файлом.
Я не проверял работу на загрузке системных или каких либо сложных dll, поэтому не могу ручаться за корректность работы кода полностью для всех случаев.

--- EN ---
This library can help to understand the PE file format (PE - Portable Executable - *.exe;*.dll;...).
The library is based on it's own data structures. But nothing can stop you from using type cast between my structures and that ones, which described inside WinNT.h.
I use my structures just because i want to clearly understand all the DOS- PE- and COFF- structures data fields.
That is not my first PE-loader library, first one was written at 2007, this is my modern reconstruction of that library.

This is a final library, which can be used for loading some small DLL file.
I can't guaranty that library will work with all DLL files you want. I never test it with system or some kind of huge DLL files.