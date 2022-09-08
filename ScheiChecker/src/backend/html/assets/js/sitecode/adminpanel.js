function lackAccess() {
  document.body.innerHTML = "<div style='filter: blur(5px);'>" + document.body.innerHTML + '</div>';
  document.body.innerHTML += `<div id="lackAccessBD" style="height: 100%;width: 100%;top: 0;left: 0;position: absolute;display: flex;align-items: center;justify-content: center;text-align: center;margin: 0px;z-index: 1000000000;"><div style=""><div style="padding: 50px;background-color: #000000cf;border-radius: 20px 20px 0px 0px;"><p>Access Denied</p><div style="display: flex;align-items: center;justify-content: center;text-align: center;"><img src="/assets/img/block.png" style="width: 5rem;aspect-ratio: 1/1;height: auto;"><p style="max-width: 50%;margin-left: 20px;">An error occoured while displaying the error.</div></div><div style="background-color: #000000cf;display: flex;border-radius: 0px 0px 20px 20px;text-align: center;width: 100%;padding: 10px 50px 10px 50px;border-top: 4px solid white;"><a href="/login.html" style="text-align: center;width: 100%;">Go back</a></div></div></div>`;
}

function accessGranted() {
  document.body.innerHTML = "<div style='filter: blur(5px);'>" + document.body.innerHTML + '</div>';
  document.body.innerHTML += `<div id="accessGrantedBD" style="height: 100%;width: 100%;top: 0;left: 0;position: absolute;display: flex;align-items: center;justify-content: center;text-align: center;margin: 0px;z-index: 1000000000;"><div style=""><div style="padding: 50px;background-color: #000000cf;border-radius: 20px 20px 0px 0px;"><p>Access Granted</p><div style="display: flex;align-items: center;justify-content: center;text-align: center;"><img style="width: 5rem;aspect-ratio: 1/1;height: auto;" src="/assets/img/ok.png"><p style="margin-left: 20px;">Mission passed, respect +<br>Redirecting in 3 seconds</p></div></div><div style="background-color: #000000cf;display: flex;border-radius: 0px 0px 20px 20px;text-align: center;width: 100%;padding: 10px 50px 10px 50px;"></div></div></div>`;
}

async function removeAlert() {
  if (
    !document.body.innerHTML.startsWith("<div style='filter: blur(5px);'>") &&
    !document.body.innerHTML.startsWith('<div style="filter: blur(5px);">')
  )
    return;
  document.body.innerHTML = document.body.innerHTML.substring(32);
  document.body.innerHTML = document.body.innerHTML.substring(
    0,
    document.body.innerHTML.length - 6
  );
  if (document.querySelector('#lackAccessBD')) document.querySelector('#lackAccessBD').remove();
  if (document.querySelector('#accessGrantedBD'))
    document.querySelector('#accessGrantedBD').remove();
}

async function accessGrantedLogin() {
  if (localStorage.lcintro) return;
  document.body.innerHTML = "<div style='filter: blur(5px);'>" + document.body.innerHTML + '</div>';
  document.body.innerHTML += `<div id="accessGrantedBD" style="height: 100%;width: 100%;top: 0;left: 0;position: absolute;display: flex;align-items: center;justify-content: center;text-align: center;margin: 0px;z-index: 1000000000;"><div style=""><div style="padding: 50px;background-color: #000000cf;border-radius: 20px 20px 0px 0px;"><p>Access Granted</p><div style="display: flex;align-items: center;justify-content: center;text-align: center;"><img style="width: 5rem;aspect-ratio: 1/1;height: auto;" src="/assets/img/check.png"><p style="margin: 0px 0px 0px 10px;text-align: left;">Mission passed, respect +<br>Redirecting in <span id="cscount"></span> seconds</p></div></div><div style="background-color: #000000cf;display: flex;border-radius: 0px 0px 20px 20px;text-align: center;width: 100%;padding: 10px 50px 10px 50px;"></div></div></div>`;
  let count = document.querySelector('#cscount');
  localStorage.lcintro = 'true';
  for (let i = 3; i > 0; i--) {
    count.innerHTML = i;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  removeAlert();
}

async function adminPanelLoad() {
  let data = await requestor('/adminAPI/isAdmin', 'GET');
  if (!data || typeof data !== 'object') return lackAccess();
  accessGrantedLogin();
  getCTFFlag();
}

async function getCTFFlag() {
  let flag = await requestor('/adminAPI/getCTFFlag', 'GET');
  document.querySelector('#adminFlag').innerText = flag;
}

async function adminExecuteChangePw() {
  let oldPw = document.querySelector('#changePwOld').value;
  let newPw = document.querySelector('#changePwNew').value;

  let resp = await requestor('/adminAPI/changePw', 'POST', { oldPw, newPw });
  if (resp) alert(resp);
}

async function adminShowRawPriceData() {
  let data = await requestor('/pricesAPI/getPrice', 'GET', { url: '/prices' });
  if (!data) {
    alert('Connection error, please reload the page');
    return;
  }
  if (data) alert(JSON.stringify(data, null, 4));
}

async function adminShowDebugInfo() {
  let data = await requestor('/adminAPI/getDebugInfo', 'GET');
  if (data) alert(data);
}

async function adminPanelLogout() {
  localStorage.removeItem('session');
  localStorage.removeItem('lcintro');
  window.location.href = '/login.html';
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
