function lackAccess() {
  document.body.innerHTML = "<div style='filter: blur(5px);'>" + document.body.innerHTML + '</div>';
  document.body.innerHTML += `<div id="lackAccessBD" style="height: 100%;width: 100%;top: 0;left: 0;position: absolute;display: flex;align-items: center;justify-content: center;text-align: center;margin: 0px;z-index: 1000000000;"><div style=""><div style="padding: 50px;background-color: #000000cf;border-radius: 20px 20px 0px 0px;"><p>Access Denied</p><div style="display: flex;align-items: center;justify-content: center;text-align: center;"><img src="/assets/img/block.png" style="width: 5rem;aspect-ratio: 1/1;height: auto;"><p style="max-width: 50%;margin-left: 20px;">An error occoured while displaying the error.</div></div><div style="background-color: #000000cf;display: flex;border-radius: 0px 0px 20px 20px;text-align: center;width: 100%;padding: 10px 50px 10px 50px;border-top: 4px solid white;"><a href="/login.html" style="text-align: center;width: 100%;">Go back</a></div></div></div>`;
}

async function indexLoad() {
  let data = await requestor('/pricesAPI/getPrice', 'GET', { url: '/prices' });
  console.log(data);
  if (!data) {
    alert('Connection error, please reload the page');
    return;
  }
  document.querySelector('#liraprice').innerText = data.price + ' ' + data.currency;
  uiResetChange();
  if (data.change === 'up') document.querySelector('#up-icon').hidden = false;
  else if (data.change === 'down') document.querySelector('#down-icon').hidden = false;
  else document.querySelector('#equals-icon').hidden = false;
  let refresh = setInterval(() => {
    let seconds = ((data.nextSync + 100 - new Date()) / 1000).toFixed(1);
    let timestamp = new Date(data.nextSync + 100).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });
    let minutes = ((data.nextSync + 100 - new Date()) / 1000 / 60).toFixed(0);
    let minutes_txt = '';
    let span = (data) =>
      `<span style="unicode-bidi: embed; font-family: monospace; white-space: pre;">${data}</span>`;
    if (minutes > 1) minutes_txt = `${span(minutes)} minutes`;
    else if (minutes === 1) minutes_txt = `${span(minutes)}  minute`;
    else if (seconds > 1) minutes_txt = `less than a minute`;

    document.querySelector('#reloadtime').innerHTML = `${span(
      seconds
    )} seconds, ${minutes_txt} (${span(timestamp)})`;
  }, 100);
  setTimeout(() => {
    indexLoad();
    clearInterval(refresh);
    document.querySelector('#reloadtime').innerText = '0 seconds';
  }, data.nextSync + 100 - new Date());
}

async function uiResetChange() {
  document.querySelector('#up-icon').hidden = true;
  document.querySelector('#down-icon').hidden = true;
  document.querySelector('#equals-icon').hidden = true;
}

async function requestor(endpoint, method, data, onlyStatus) {
  try {
    let headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json'
    };
    if (localStorage.getItem('session'))
      headers['Authorization'] = 'Bearer ' + localStorage.getItem('session');
    let options = {
      headers: {}
    };
    let query = '';
    if (method && method !== 'HEAD' && method !== 'GET' && method !== 'DELETE' && data) {
      options.body = JSON.stringify(data);
      options.headers = {};
      options.headers['Content-Type'] = 'application/json';
      options.method = method;
    } else {
      if (typeof data === 'object') {
        query = new URLSearchParams(data).toString();
      }
      options.method = method ?? 'GET';
    }
    if (localStorage.getItem('session'))
      options.headers['Authorization'] = 'Bearer ' + localStorage.getItem('session');
    let request = await fetch(`${endpoint}?${query}`, options);
    if (onlyStatus) return request.status;
    if (request.status === 400) return;
    if (request.status === 200) return request.json();
    if (request.status === 403) throw new Error('lackAccess');
    if (request.status === 429) throw new Error('rateLimit');
    if (request.status === 502) throw new Error('proxyError');
    return request.text();
  } catch (e) {
    if (e.message === 'lackAccess') {
      localStorage.removeItem('session');
      localStorage.removeItem('lcintro');
      throw new Error(lackAccess());
    }
    if (e.message === 'rateLimit')
      throw new Error(alert('Too many requests! Please try again later.'));
    console.error(e);
    alert('Connection error');
    return null;
  }
}
