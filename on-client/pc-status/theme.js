// 화면 테마(밝은 / 어두운)와 유리 효과(꺼짐 / 반투명 / 완전 투과)를 첫 그리기 전에 적용해서 깜빡임을 막는다.
// 저장 위치는 이 브라우저의 localStorage 뿐이다.
(function () {
  var theme = 'light', glass = 'on';
  try {
    if (localStorage.getItem('soc.theme') === 'dark') theme = 'dark';
    var saved = localStorage.getItem('soc.glass');
    if (saved === 'off' || saved === 'clear') glass = saved;
  } catch (e) { /* 저장소를 못 읽으면 기본값 */ }
  document.documentElement.setAttribute('data-theme', theme);
  document.documentElement.setAttribute('data-glass', glass);
})();
