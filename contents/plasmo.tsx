import cssText from 'data-text:~globals.css';
import type {
  PlasmoCSConfig,
  PlasmoCSUIJSXContainer,
  PlasmoCSUIProps,
  PlasmoGetInlineAnchor,
  PlasmoGetOverlayAnchor,
  PlasmoGetShadowHostId,
  PlasmoGetStyle,
  PlasmoRender,
} from 'plasmo';

import Popup from '~popup';
import styleText from 'data-text:../globals.css';
export const config: PlasmoCSConfig = {
  matches: ['https://x.com/*'],
  // matches: ["https://www.baidu.com/*"],
};
export const getStyle: PlasmoGetStyle = () => {
  const style = document.createElement('style');
  style.textContent = styleText;
  return style;
};
export const getInlineAnchor: PlasmoGetInlineAnchor = async () =>
  // document.querySelector(
  //   "div[data-testid='sidebarColumn'] > div > div:nth-child(2) > div > div > div > div:nth-child(2)"
  // );
  document.querySelector("#react-root > div > div > div > main > div > div > div > div > div > div > div > div > div > div:nth-child(3)")
  // #react-root > div > div > div.css-175oi2r.r-1f2l425.r-13qz1uu.r-417010.r-18u37iz > main > div > div > div > div.css-175oi2r.r-aqfbo4.r-10f7w94.r-1hycxz > div > div.css-175oi2r.r-1hycxz.r-gtdqiz > div > div > div > div.css-175oi2r.r-1awozwy.r-aqfbo4.r-14lw9ot.r-18u37iz.r-1h3ijdo.r-6gpygo.r-15ysp7h.r-1xcajam.r-ipm5af.r-136ojw6.r-1hycxz
// document.querySelector("div[id='lg']");
// export const getRootContainer = () => {
//   let div = document.createElement('div');
//   div.classList.add('fffff');
//   return div;
// };

export default Popup;
