let subscribeNowReady = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}

subscribeNowReady(() => {
    const subscribeNowForm = document.querySelector("#subscribe");
    const buttonInput = subscribeNowForm.querySelector("button[type=submit]");
    const emailInput = subscribeNowForm.querySelector("input[type=email]");

    buttonInput.addEventListener("click", (event) => {
        event.preventDefault();
        if (!emailInput.checkValidity()) {
            emailInput.reportValidity();
            return;
        }

        const formInputs = subscribeNowForm.querySelectorAll("input");
        const value = Array.from(formInputs)
                .reduce((obj, formInput) => {
                    return {
                        ...obj,
                        [formInput.name]: formInput.value,
                    };
                }, {});
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (this.readyState == 4) {
                const responseJson = JSON.parse(this.responseText);
                const formParent = subscribeNowForm.parentElement;
                const div = document.createElement("div");
                div.classList.add('newsletter-signup-response');
                if (this.status == 200) {
                    if (responseJson.email) {
                        const emailDiv = document.createElement("div");
                        emailDiv.classList.add('email-signup-confirm');
                        const email = document.createElement("p");
                        email.textContent = responseJson.email;
                        emailDiv.appendChild(email);
                        div.appendChild(emailDiv);
                    }
                    const header = document.createElement("h3");
                    header.textContent = 'Thank you for Subscribing';
                    div.appendChild(header);
                    subscribeNowForm.replaceWith(div)

                    if (responseJson.coupon) {
                        const coupon = document.getElementById("copyable-coupon");
                        coupon.textContent = responseJson.coupon;
                    }

                    const dialog = document.getElementById("coupon-dialog");
                    dialog.showModal();
                } else {
                    const header = document.createElement("h3");
                    header.textContent = 'Error Subscribing';
                    div.classList.add('error');
                    div.appendChild(header);
                    // formParent.appendChild(div);
                    subscribeNowForm.replaceWith(div)
                }
            }
        };
        xhr.open(subscribeNowForm.dataset.method, subscribeNowForm.dataset.action);
        xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
        xhr.send(JSON.stringify(value));
    });
});

const closeCouponDialog = (e) => {
    e.preventDefault();

    const dialog = document.getElementById("coupon-dialog");
    dialog.close();
};

const copyCoupon = async (e) => {
    e.preventDefault();
    const copyableCoupon = document.getElementById("copyable-coupon");
    try {
        await navigator.clipboard.writeText(copyableCoupon.textContent);

        const tick = document.getElementById("coupon-copied-tick");
        tick.setAttribute("class", "coupon-copied-tick")

        copyableCoupon.textContent = "Copied";
        const copyCouponButton = document.getElementById("copy-coupon-button");
        copyCouponButton.className += " hidden";
    } catch (err) {
        console.error('Failed to copy: ', err);
    }
};