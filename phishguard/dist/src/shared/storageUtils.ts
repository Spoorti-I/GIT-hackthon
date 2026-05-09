export const getStorage = (keys: string | string[] | Object): Promise<any> => {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => {
      resolve(result);
    });
  });
};

export const setStorage = (data: Object): Promise<void> => {
  return new Promise((resolve) => {
    chrome.storage.local.set(data, () => {
      resolve();
    });
  });
};

export const getSyncStorage = (keys: string | string[] | Object): Promise<any> => {
  return new Promise((resolve) => {
    chrome.storage.sync.get(keys, (result) => {
      resolve(result);
    });
  });
};

export const setSyncStorage = (data: Object): Promise<void> => {
  return new Promise((resolve) => {
    chrome.storage.sync.set(data, () => {
      resolve();
    });
  });
};
