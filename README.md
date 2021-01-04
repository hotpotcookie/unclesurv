# UncleSurv //

UncleSurv ( Under Close Surveillance ) is a simple bash-based program that is designated to prevent DoS threat, which is specialized for ICMP Flood attack. The program itself has 2 modes that are adapted from IDS and IPS functionality, so it may detect, notify, and deflect the potential threat based on the parameter that has been set up on a JSON file.

The decision method will be taken from the client's ping activity toward the machine/server. When the sequence reaches the max parameter, the program will automatically call out the client's IP to be issued with IPTABLES for further management of its connection. User can also add their own rules manually that later to be also added to the saved logs, so it will automatically load the rules whenever the program is about to run.

## Install Dependencies

UncleSurv has not made it into the deb packages yet :3, therefore, you can either clone the repository or simply download the zip format.
```bash
$ git clone https://github.com/hotpotcookie/unclesurv.git
$ cd unclesurv/
```
```bash
$ wget https://github.com/hotpotcookie/unclesurv/archive/main.zip
$ unzip main.zip -d unclesurv
$ cd unclesurv/
```

## Usage

```python
import foobar

foobar.pluralize('word') # returns 'words'
foobar.pluralize('goose') # returns 'geese'
foobar.singularize('phenomena') # returns 'phenomenon'
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
