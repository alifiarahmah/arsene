

let navTrigger = document.querySelector(".nav-trigger");
let body = document.querySelector("body");
let navTarget = document.querySelector("nav");

let ready = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}

ready(() => {
    const isHomePage = document.querySelector("[theme='home']");
    const isCartPage= document.querySelector("[theme='cart']");
    const isAboutPage= document.querySelector("[theme='about']");
    const isLoginPage= document.querySelector("[theme='login']");

    navTrigger.addEventListener("click", () => {
        body.classList.toggle("active-nav");
        navTarget.classList.toggle("active-nav");
    });

    body.addEventListener("click", () => {
        // target.classList.remove("active-nav");
    });

    if(isHomePage) {
        const carousel = document.getElementsByClassName('productsPreviewList')[0];

        // add the left/right controls
        let prevBtn = document.createElement("div");
        prevBtn.classList.add('prev-arrow');
        prevBtn.onclick = prev;
        carousel.prepend(prevBtn);
        let nextBtn = document.createElement("div");
        nextBtn.classList.add('next-arrow');
        nextBtn.onclick = next;
        carousel.append(nextBtn);

        // add a wrapping div for the carousel
        const containerList = document.getElementsByClassName('container-list-tiles')[0];
        const carouselWrapper = document.createElement('div');
        carouselWrapper.classList.add('container-list-wrapper');
        containerList.parentElement.insertBefore(carouselWrapper, containerList);
        carouselWrapper.append(containerList);

        // add some stuff for the title banner
        const titleBanner = document.getElementsByClassName('titleBanner')[0];
        const glowDiv = document.createElement('div');
        glowDiv.classList.add('glow');
        titleBanner.append(glowDiv);
        const bottleOne = document.createElement('img');
        bottleOne.classList.add('bottleOne');
        bottleOne.src = '/resources/images/heyes_bottle.png';
        const bottleTwo = document.createElement('img');
        bottleTwo.classList.add('bottleTwo');
        bottleTwo.src = '/resources/images/kettle_bottle.png';
        const bottleThree = document.createElement('img');
        bottleThree.classList.add('bottleThree');
        bottleThree.src = '/resources/images/g_j_bottle.png';
        glowDiv.append(bottleOne, bottleThree, bottleTwo);

        // move it all into the main container
        const maincontainer = document.getElementsByClassName('maincontainer')[0];
        maincontainer.prepend(titleBanner);

    }

    if(isCartPage) {

        // add a body class for the cart as we need to style it higher than the theme selector
        const body = document.querySelector("body");
        body.classList.add('is-cart');

        // sort out the p heading
        const headingParent = document.querySelector("[theme='cart'] header+p").parentNode;
        const oldHeading = document.querySelector("[theme='cart'] header+p");
        let newHeading = document.createElement("h1");
        let newHeadingText = document.createTextNode("Shopping cart");
        newHeading.appendChild(newHeadingText);
        headingParent.insertBefore(newHeading, oldHeading);
        oldHeading.remove();

        // create a better layout and seperate the coupon parts

    }

    if(isAboutPage) {
        //TODO: Implementation here.
        const titleBanner = document.getElementsByClassName('titleBanner')[0];
        const glowDiv = document.createElement('div');
        glowDiv.classList.add('glow');
        titleBanner.append(glowDiv);
        const bottleOne = document.createElement('img');
        bottleOne.classList.add('bottleOne');
        bottleOne.src = '/resources/images/batch1337_can.png';
        const bottleTwo = document.createElement('img');
        bottleTwo.classList.add('bottleTwo');
        bottleTwo.src = '/resources/images/dry_SQLI_can.png';
        const bottleThree = document.createElement('img');
        bottleThree.classList.add('bottleThree');
        bottleThree.src = '/resources/images/pineapple-can.png';
        glowDiv.append(bottleOne, bottleThree, bottleTwo);

        // move it all into the main container
        const maincontainer = document.getElementsByClassName('maincontainer')[0];
        maincontainer.prepend(titleBanner);
    }

    if(isLoginPage) {
        body.classList.add('is-login')
    }

    let currentIndex = 0;
    let slides = [];

    function render() {
        const sectionContainer = document.querySelector(".has-carousel");
        let offset = 0;
        slides.forEach((slide, index) => {
            if (index < currentIndex) {
                offset += slide.offsetWidth;
            }
        });

        sectionContainer.style.transform = `translateX(-${offset}px)`;
    }

    function prev() {
        if (currentIndex < 0) return;
        currentIndex -= 1;
        render();
    }

    function next() {
        if (currentIndex === slides.length - 1) currentIndex = -1;
        currentIndex += 1;
        render();
    }

    function goto(newIndex) {
        if (newIndex < 0 || newIndex > slides.length - 1) return;
        currentIndex = newIndex;
        render();
    }

    function init() {

        const newSlides = document.querySelectorAll(".has-carousel > a");
        slides = newSlides;

        render();
    }

    function destroy() {
        const sectionContainer = document.querySelector(".container-list-tiles");
        sectionContainer.style.transform = null;

    }

    const sliderWrapper = document.querySelector('.productsPreviewList .container-list-tiles');

    if (sliderWrapper)
    {
        const observer = new ResizeObserver(entries => {
            entries.forEach(entry => {
                if(entry.contentRect.width < 625 && entry.target.classList.contains('container-list-tiles')) {
                    entry.target.classList.add('has-carousel');
                    init();
                } else {
                    entry.target.classList.remove('has-carousel');
                    destroy();
                }
            });
        });

        observer.observe(sliderWrapper);
    }
});