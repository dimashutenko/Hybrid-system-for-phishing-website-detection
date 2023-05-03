var myHeaders = new Headers();
              myHeaders.append("Content-Type", "application/json");

              var raw = "{ 'client': {'clientId':'Dmytro_Shutenko','clientVersion':'1.0.1'}, 'threatInfo': {'threatTypes':['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],'platformTypes':['ANY_PLATFORM'],'threatEntryTypes': ['URL'], 'threatEntries': [ {'url': 'https://www.ysor.fit/'}, {'url': 'http://cs42041.tw1.ru/'}, {'url': 'http://whattsap.xyz/'} ] } }";

              var requestOptions = {
                method: 'POST',
                headers: myHeaders,
                body: raw,
                redirect: 'follow'
              };

              fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyD5_odg6Etmv_f5coTMEHJpm6GeUDIXFcs", requestOptions)
                .then(response => response.text())
                .then(result => console.log(result))
                .catch(error => console.log('error', error));

              let response = await fetch('/search?q=' + input.value);
                let shows = await response.text();
                document.querySelector('ul').innerHTML = shows;